"""L6 Output Layer -- Validation Suite.

Tests all 12 scenarios from the AgentArmor L6 Output Security Spec.
Run: uv run python desktop/sidecar/test_l6_validation.py
"""
from __future__ import annotations

import os
import sys
import time

# Ensure agentarmor is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from agentarmor.layers.output.filter import (
    L6OutputLayer,
    _get_presidio,
    get_output_context,
)

PASS = "[PASS]"
FAIL = "[FAIL]"

results: list[tuple[str, bool, str]] = []

def record(name: str, passed: bool, detail: str = ""):
    results.append((name, passed, detail))
    status = PASS if passed else FAIL
    print(f"  {status}  {name}")
    if detail and not passed:
        print(f"         {detail}")


def main():
    print("=" * 60)
    print("AgentArmor L6 Output Layer -- Validation Suite")
    print("=" * 60)

    t0 = time.time()
    
    # Pre-warm presidio
    _get_presidio()
    
    l6 = L6OutputLayer(agent_id="test-agent")

    # =====================================================================
    print("\n-- Test 1: AWS Key Redaction (Credential Scanner) --")
    t1_in = 'Your AWS access key is AKIAIOSFODNN7EXAMPLE and secret="abc123xyz"'
    t1_out, t1_evt = l6.process(t1_in, "t1")
    record("AWS Access Key redacted", "[REDACTED:AWS_ACCESS_KEY]" in t1_out, f"Got: {t1_out}")
    record("2 credentials redacted", t1_evt["credentials_redacted"] == 2, f"Got {t1_evt['credentials_redacted']}")
    record("Threat level is critical", t1_evt["threat_level"] == "critical", f"Got: {t1_evt['threat_level']}")

    # =====================================================================
    print("\n-- Test 2: JWT Token Redaction --")
    t2_in = "Here is the token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.abc123signature456"
    t2_out, t2_evt = l6.process(t2_in, "t2")
    record("JWT Token redacted", "[REDACTED:JWT_TOKEN]" in t2_out, f"Got: {t2_out}")

    # =====================================================================
    print("\n-- Test 3: Database Connection String --")
    t3_in = "postgresql://admin:password123@prod.db.company.internal:5432/users"
    t3_out, t3_evt = l6.process(t3_in, "t3")
    record("DB Connection String redacted", "[REDACTED:DB_CONNECTION_STRING]" in t3_out, f"Got: {t3_out}")

    # =====================================================================
    print("\n-- Test 4: PII False Positive Gating --")
    t4_in = "The package version is 3.1.0 and the build ID is US_BUILD_22."
    t4_out, t4_evt = l6.process(t4_in, "t4")
    record("No PII redacted", t4_evt["pii_redacted"] == 0, f"Got: {t4_evt['pii_redacted']}")
    record("Text untouched", t4_out == t4_in, f"Got: {t4_out}")

    # =====================================================================
    print("\n-- Test 5: PII Real Detection --")
    t5_in = "John Smith's phone is 555-123-4567 and his email is john.smith@example.com"
    t5_out, t5_evt = l6.process(t5_in, "t5")
    record("[PERSON] redacted", "[PERSON]" in t5_out, f"Got: {t5_out}")
    record("[PHONE_NUMBER] redacted", "[PHONE_NUMBER]" in t5_out, f"Got: {t5_out}")
    record("[EMAIL_ADDRESS] redacted", "[EMAIL_ADDRESS]" in t5_out, f"Got: {t5_out}")
    record("PII count > 0", t5_evt["pii_redacted"] >= 2, f"Got: {t5_evt['pii_redacted']}")

    # =====================================================================
    print("\n-- Test 6: System Prompt Leak --")
    t6_in = "My system prompt says: [AGENTARMOR-SYSTEM-IMMUTABLE] You are an AI assistant..."
    t6_out, t6_evt = l6.process(t6_in, "t6")
    record("Verdict is block", t6_evt["verdict"] == "block", f"Got: {t6_evt['verdict']}")
    record("Threat is system_prompt_leak", any(f.get("threat") == "system_prompt_leak" for f in t6_evt["findings"]), f"Findings: {t6_evt['findings']}")
    record("Blocked message returned", "[AgentArmor L6 BLOCKED]" in t6_out, f"Got: {t6_out[:30]}")

    # =====================================================================
    print("\n-- Test 7: Canary Token Leak --")
    t7_in = "The secret identifier is CANARY-a1b2c3d4xyz"
    t7_out, t7_evt = l6.process(t7_in, "t7")
    record("Verdict is block", t7_evt["verdict"] == "block", f"Got: {t7_evt['verdict']}")

    # =====================================================================
    print("\n-- Test 8: Semantic Exfiltration (Session context) --")
    session = "t8_exfil_session"
    l6.process("Contact support@corp.com or call 555-123-4567", session)
    l6.process("Manager is Jane Doe and email is other@corp.com", session)
    # Give it another load of entities
    t8_out, t8_evt = l6.process("More people: Alice, Bob, Charlie, Dave, and emails a@b.com, b@c.com, c@d.com, d@e.com", session)
    record("Semantic Exfiltration Flagged", t8_evt["semantic_exfiltration_flag"] is True, f"Evt: {t8_evt}")
    record("Verdict is flagged or block", t8_evt["verdict"] in ("flagged", "redacted", "block"), f"Got: {t8_evt['verdict']}")

    # =====================================================================
    print("\n-- Test 9: Private IP Redaction --")
    t9_in = "The Redis cache is at 10.0.0.45:6379 and DB replica at 192.168.1.100"
    t9_out, t9_evt = l6.process(t9_in, "t9")
    record("IPs redacted", "[REDACTED:PRIVATE_IP]" in t9_out, f"Got: {t9_out}")
    record("Credentials count = 2", t9_evt["credentials_redacted"] == 2, f"Got: {t9_evt['credentials_redacted']}")

    # =====================================================================
    print("\n-- Test 10: Clean Response --")
    t10_in = "Here is a quick Python script to calculate the Fibonacci sequence."
    t10_out, t10_evt = l6.process(t10_in, "t10")
    record("Findings count = 0", t10_evt["findings_count"] == 0, f"Got: {t10_evt['findings_count']}")
    record("Verdict = allow", t10_evt["verdict"] == "allow", f"Got: {t10_evt['verdict']}")

    # =====================================================================
    print("\n-- Test 11: Streaming Buffer Flush --")
    buf = []
    chunk1, _ = l6.process_streaming_chunk("The key is AKIA", "t11", buf)
    chunk2, evt2 = l6.process_streaming_chunk("IOSFODNN7EXAMPLE. ", "t11", buf)
    record("First chunk accumulates", chunk1 == "The key is AKIA", f"Got: {chunk1}")
    record("Second chunk triggers flush", evt2 is not None, f"Got: evt={evt2}")
    if evt2:
        record("Credential found in flush", evt2["credentials_redacted"] > 0, f"Got: {evt2}")

    # =====================================================================
    print("\n-- Test 12: Latency Benchmark --")
    t_start = time.perf_counter()
    l6_bench = L6OutputLayer("bench")
    iters = 20
    for _ in range(iters):
        l6_bench.process("Here is a clean response with ~20 words that evaluates the scanner overhead safely.", "bench")
    t_end = time.perf_counter()
    avg_ms = ((t_end - t_start) * 1000) / iters
    record(f"Average latency < 100ms (got {avg_ms:.1f}ms)", avg_ms < 100.0, f"Got: {avg_ms:.1f}ms")

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


if __name__ == "__main__":
    main()
