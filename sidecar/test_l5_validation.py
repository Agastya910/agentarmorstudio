"""L5 Execution Layer -- Validation Suite.

Tests all 8 scenarios from the AgentArmor L5 Execution Layer Spec.
Run: uv run python desktop/sidecar/test_l5_validation.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time

# Ensure agentarmor is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from agentarmor.layers.execution.l5_execution import (
    L5ExecutionLayer,
    NetworkPolicy,
    RateConfig,
    RateLimiterRegistry,
    ResourceBudget,
    TokenBucket,
    enforce_network_policy,
    execute_with_timeout,
    resolve_and_check_ip,
    sanitize_tool_output,
)

PASS = "\033[92m\u2713 PASS\033[0m"
FAIL = "\033[91m\u2717 FAIL\033[0m"

results: list[tuple[str, bool, str]] = []


def record(name: str, passed: bool, detail: str = ""):
    results.append((name, passed, detail))
    status = PASS if passed else FAIL
    print(f"  {status}  {name}")
    if detail and not passed:
        print(f"         {detail}")


# =====================================================================
# TEST 1: DNS Rebinding SSRF Defense
# =====================================================================

def test_dns_rebinding():
    print("\n-- Test 1: DNS Rebinding SSRF Defense --")

    # localhost resolves to 127.0.0.1 which is in PRIVATE_RANGES
    policy = NetworkPolicy(allow_http=True, dns_rebinding_protection=True)
    result = enforce_network_policy("http://localhost/admin", policy)

    record(
        f"localhost verdict = {result['verdict']} (expected block)",
        result["verdict"] == "block",
        f"Got: {result}"
    )
    record(
        f"reason contains 'dns_rebinding_ssrf' (got {result.get('reason', '')})",
        "dns_rebinding_ssrf" in result.get("reason", ""),
        f"Got: {result.get('reason')}"
    )

    # 127.0.0.1 directly
    result2 = enforce_network_policy("http://127.0.0.1:8080/api", policy)
    record(
        f"127.0.0.1 verdict = {result2['verdict']} (expected block)",
        result2["verdict"] == "block",
        f"Got: {result2}"
    )

    # Safe external URL should pass
    result3 = enforce_network_policy("https://api.example.com/data", policy)
    record(
        f"api.example.com verdict = {result3['verdict']} (expected allow)",
        result3["verdict"] == "allow",
        f"Got: {result3}"
    )


# =====================================================================
# TEST 2: Rate Limiting -- Token Bucket Burst + Sustained
# =====================================================================

def test_rate_limiting():
    print("\n-- Test 2: Rate Limiting -- Token Bucket --")

    config = RateConfig(burst_limit=5, refill_rate=0.5)
    bucket = TokenBucket(config, "tool_web_search", "test-agent")

    # Fire 8 requests quickly
    request_results = []
    for i in range(8):
        allowed, reason = bucket.try_consume()
        request_results.append((allowed, reason))

    # First 5 should succeed
    first_5_ok = all(r[0] for r in request_results[:5])
    record(
        f"First 5 requests allowed = {first_5_ok} (expected True)",
        first_5_ok,
        f"Results: {request_results[:5]}"
    )

    # Requests 6-8 should be blocked
    last_3_blocked = not any(r[0] for r in request_results[5:])
    record(
        f"Requests 6-8 blocked = {last_3_blocked} (expected True)",
        last_3_blocked,
        f"Results: {request_results[5:]}"
    )

    # Check that the blocked reason mentions rate_limited
    record(
        f"Block reason mentions 'rate_limited' = {request_results[5][1]}",
        "rate_limited" in request_results[5][1],
        f"Got: {request_results[5][1]}"
    )

    # After waiting for 2 tokens to refill (4 seconds at 0.5/s), 2 more should be allowed
    time.sleep(4.1)
    refill_1, _ = bucket.try_consume()
    refill_2, _ = bucket.try_consume()
    record(
        f"After 4s wait, 2 more requests allowed = {refill_1 and refill_2}",
        refill_1 and refill_2,
        f"Got: refill_1={refill_1}, refill_2={refill_2}"
    )


# =====================================================================
# TEST 3: Execution Timeout
# =====================================================================

def test_execution_timeout():
    print("\n-- Test 3: Execution Timeout --")

    async def slow_tool(**kwargs):
        await asyncio.sleep(60)
        return "should not reach here"

    budget = ResourceBudget(execution_timeout_s=1.0, max_output_bytes=1000)

    async def run():
        t0 = time.time()
        result, success, reason = await execute_with_timeout(
            slow_tool, "test_slow_tool", {}, budget
        )
        elapsed = time.time() - t0
        return result, success, reason, elapsed

    result, success, reason, elapsed = asyncio.run(run())

    record(
        f"Timeout success = {success} (expected False)",
        success is False,
        f"Got: {success}"
    )
    record(
        f"Reason contains 'timeout' = {reason}",
        "timeout" in reason,
        f"Got: {reason}"
    )
    record(
        f"Result has L5 TIMEOUT message",
        "[L5 TIMEOUT]" in str(result.get("error", "")),
        f"Got: {result}"
    )
    record(
        f"Elapsed ~1s = {elapsed:.1f}s (expected ~1.0)",
        0.9 < elapsed < 2.0,
        f"Got: {elapsed:.2f}s"
    )


# =====================================================================
# TEST 4: Output Size Enforcement
# =====================================================================

def test_output_size_enforcement():
    print("\n-- Test 4: Output Size Enforcement --")

    # Create a 5MB output
    large_output = "A" * (5 * 1024 * 1024)  # 5MB

    budget = ResourceBudget(execution_timeout_s=5.0, max_output_bytes=200_000)  # 200KB limit

    sanitized, warnings = sanitize_tool_output(large_output, "tool_file_read", budget)

    record(
        f"Output was truncated (warnings has 'output_truncated')",
        any("output_truncated" in w for w in warnings),
        f"Warnings: {warnings}"
    )
    record(
        f"Sanitized output ends with L5 truncation notice",
        "[L5: Output truncated" in sanitized,
        f"Last 100 chars: {sanitized[-100:]}"
    )
    record(
        f"Sanitized output size <= budget (got {len(sanitized.encode())} bytes)",
        len(sanitized.encode()) <= budget.max_output_bytes + 200,  # Allow for truncation notice
        f"Got: {len(sanitized.encode())} bytes, budget: {budget.max_output_bytes}"
    )


# =====================================================================
# TEST 5: Binary Content Blocking
# =====================================================================

def test_binary_content():
    print("\n-- Test 5: Binary Content Blocking --")

    # Create a string with >30% non-printable control characters
    # This simulates what a binary response would look like after UTF-8 decoding
    printable = "ABCDEFGHIJabcdef"  # 16 printable chars
    non_printable = "".join(chr(i) for i in range(1, 15))  # 14 control chars (excluding \n \r \t \x00)
    # Ratio: 14/(16+14) = 46.7% non-printable
    binary_str = (non_printable + printable) * 50

    sanitized, warnings = sanitize_tool_output(binary_str, "tool_web_fetch")

    record(
        f"Binary content detected in warnings",
        "binary_content_detected_stripped" in warnings,
        f"Warnings: {warnings}"
    )
    record(
        f"Output is blocked message (not raw binary)",
        "Binary content detected and blocked" in sanitized,
        f"Got: {sanitized[:80]}"
    )


# =====================================================================
# TEST 6: Circuit Breaker
# =====================================================================

def test_circuit_breaker():
    print("\n-- Test 6: Circuit Breaker --")

    config = RateConfig(burst_limit=10, refill_rate=1.0, failure_threshold=2, recovery_timeout=2.0)
    bucket = TokenBucket(config, "tool_run_code", "test-agent")

    # Record 2 failures (threshold = 2)
    bucket.record_failure()
    bucket.record_failure()

    # Circuit should now be open
    allowed, reason = bucket.try_consume()
    record(
        f"After 2 failures, circuit open = {not allowed} (expected True)",
        not allowed,
        f"Got: allowed={allowed}, reason={reason}"
    )
    record(
        f"Reason mentions 'circuit_open' = {reason}",
        "circuit_open" in reason,
        f"Got: {reason}"
    )

    # Wait for recovery (2 seconds)
    time.sleep(2.1)

    # Circuit should half-open and allow one probe
    allowed2, reason2 = bucket.try_consume()
    record(
        f"After recovery timeout, circuit half-open = {allowed2} (expected True)",
        allowed2,
        f"Got: allowed={allowed2}, reason={reason2}"
    )


# =====================================================================
# TEST 7: Outbound Payload Size (AARF Exfiltration Defense)
# =====================================================================

def test_outbound_payload_limit():
    print("\n-- Test 7: Outbound Payload Size (AARF Defense) --")

    policy = NetworkPolicy(max_outbound_payload_bytes=50_000, allow_http=True, dns_rebinding_protection=False)

    # 100KB payload (above 50KB limit)
    large_payload = "X" * 100_000

    result = enforce_network_policy(
        "https://webhook.site/test-id", policy, outbound_payload=large_payload
    )

    record(
        f"Large payload verdict = {result['verdict']} (expected block)",
        result["verdict"] == "block",
        f"Got: {result}"
    )
    record(
        f"Reason mentions 'outbound_payload_too_large'",
        "outbound_payload_too_large" in result.get("reason", ""),
        f"Got: {result.get('reason')}"
    )

    # Small payload should pass
    small_payload = "test data"
    result2 = enforce_network_policy(
        "https://webhook.site/test-id", policy, outbound_payload=small_payload
    )
    record(
        f"Small payload verdict = {result2['verdict']} (expected allow)",
        result2["verdict"] == "allow",
        f"Got: {result2}"
    )


# =====================================================================
# TEST 8: Side-Effect Audit Trail
# =====================================================================

def test_side_effect_audit():
    print("\n-- Test 8: Side-Effect Audit Trail --")

    async def mock_web_search(**kwargs):
        return {"results": [{"title": "Test", "url": "https://example.com"}]}

    async def mock_db_query(**kwargs):
        return {"rows": [{"id": 1, "name": "Test"}]}

    async def mock_file_read(**kwargs):
        return "File content here"

    async def run():
        l5 = L5ExecutionLayer(
            "audit-test-agent",
            NetworkPolicy(allow_http=True, dns_rebinding_protection=False),
        )
        session = "test-audit-session"

        # Run 3 tools
        await l5.execute("tool_web_search", {"query": "Python tutorials"},
                         mock_web_search, session)
        await l5.execute("tool_db_query", {"sql": "SELECT * FROM products"},
                         mock_db_query, session)
        await l5.execute("tool_file_read", {"path": "README.md"},
                         mock_file_read, session)

        return l5.get_session_side_effects(session)

    side_effects = asyncio.run(run())

    record(
        f"Side effects count = {len(side_effects)} (expected 3)",
        len(side_effects) == 3,
        f"Got: {len(side_effects)}"
    )

    if len(side_effects) >= 3:
        record(
            f"First tool = {side_effects[0]['tool']} (expected tool_web_search)",
            side_effects[0]["tool"] == "tool_web_search",
            f"Got: {side_effects[0]['tool']}"
        )
        record(
            f"Second tool = {side_effects[1]['tool']} (expected tool_db_query)",
            side_effects[1]["tool"] == "tool_db_query",
            f"Got: {side_effects[1]['tool']}"
        )
        record(
            f"Third tool = {side_effects[2]['tool']} (expected tool_file_read)",
            side_effects[2]["tool"] == "tool_file_read",
            f"Got: {side_effects[2]['tool']}"
        )
        record(
            f"All tools succeeded",
            all(se["success"] for se in side_effects),
            f"Success values: {[se['success'] for se in side_effects]}"
        )
        record(
            f"Duration values are positive",
            all(se["duration_ms"] >= 0 for se in side_effects),
            f"Durations: {[se['duration_ms'] for se in side_effects]}"
        )
        record(
            f"Web search has URL in side effect",
            len(side_effects[0].get("urls", [])) > 0,
            f"URLs: {side_effects[0].get('urls', [])}"
        )


# =====================================================================
# TEST 9: Protocol Blocking
# =====================================================================

def test_protocol_blocking():
    print("\n-- Test 9: Protocol Blocking --")

    policy = NetworkPolicy(allow_http=True, dns_rebinding_protection=False)

    # file:// should be blocked
    result = enforce_network_policy("file:///etc/passwd", policy)
    record(
        f"file:// verdict = {result['verdict']} (expected block)",
        result["verdict"] == "block",
        f"Got: {result}"
    )

    # gopher:// should be blocked
    result2 = enforce_network_policy("gopher://evil.com/payload", policy)
    record(
        f"gopher:// verdict = {result2['verdict']} (expected block)",
        result2["verdict"] == "block",
        f"Got: {result2}"
    )

    # HTTPS enforcement when allow_http=False
    strict_policy = NetworkPolicy(allow_http=False, dns_rebinding_protection=False)
    result3 = enforce_network_policy("http://api.example.com/data", strict_policy)
    record(
        f"HTTP with allow_http=False verdict = {result3['verdict']} (expected block)",
        result3["verdict"] == "block",
        f"Got: {result3}"
    )
    record(
        f"Reason = {result3.get('reason')} (expected http_not_allowed...)",
        "http_not_allowed" in result3.get("reason", ""),
        f"Got: {result3.get('reason')}"
    )


# =====================================================================
# TEST 10: Full L5 Pipeline Integration
# =====================================================================

def test_full_pipeline():
    print("\n-- Test 10: Full L5 Pipeline Integration --")

    async def mock_safe_tool(**kwargs):
        return {"status": "ok", "data": "safe response"}

    async def run():
        l5 = L5ExecutionLayer(
            "pipeline-test-agent",
            NetworkPolicy(allow_http=True, dns_rebinding_protection=False),
        )

        # Normal tool call should pass all gates
        result, event = await l5.execute(
            "tool_file_read", {"path": "README.md"},
            mock_safe_tool, "pipeline-session",
        )
        return result, event

    result, event = asyncio.run(run())

    record(
        f"Full pipeline verdict = {event['verdict']} (expected allow)",
        event["verdict"] == "allow",
        f"Got: {event}"
    )
    record(
        f"Event has layer = L5_Execution",
        event.get("layer") == "L5_Execution",
        f"Got: {event.get('layer')}"
    )
    record(
        f"Event has execution_ms",
        "execution_ms" in event,
        f"Got keys: {list(event.keys())}"
    )
    record(
        f"Event has verdicts list",
        "verdicts" in event and len(event["verdicts"]) > 0,
        f"Verdicts: {event.get('verdicts')}"
    )
    record(
        f"Result is a string (sanitized output)",
        isinstance(result, str),
        f"Got type: {type(result)}"
    )


# =====================================================================
# MAIN
# =====================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("AgentArmor L5 Execution Layer -- Validation Suite")
    print("=" * 60)

    t0 = time.time()

    test_dns_rebinding()
    test_rate_limiting()
    test_execution_timeout()
    test_output_size_enforcement()
    test_binary_content()
    test_circuit_breaker()
    test_outbound_payload_limit()
    test_side_effect_audit()
    test_protocol_blocking()
    test_full_pipeline()

    elapsed = time.time() - t0

    print("\n" + "=" * 60)
    passed = sum(1 for _, p, _ in results if p)
    total = len(results)
    failed = total - passed

    if failed == 0:
        print(f"\033[92mAll {total} checks passed in {elapsed:.2f}s\033[0m")
    else:
        print(f"\033[91m{failed}/{total} checks FAILED in {elapsed:.2f}s\033[0m")
        print("\nFailed checks:")
        for name, p, detail in results:
            if not p:
                print(f"  x {name}: {detail}")

    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)
