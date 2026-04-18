"""L7 Inter-Agent Layer — Validation Suite.

Tests all 15 scenarios from the AgentArmor L7 Hardening Spec.
Run: uv run python desktop/sidecar/test_l7_validation.py
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from agentarmor.layers.interagent.l7_interagent import (
    ANOMALY_BLOCK_THRESHOLD,
    BehavioralBaseline,
    DelegationCertificate,
    DirectedTrustStore,
    L7InterAgentLayer,
    NonceRegistry,
    VerifyResult,
    _nonce_registry,
    create_delegation,
    create_signed_payload,
    verify_delegated_action,
    verify_message,
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
    print("AgentArmor L7 Inter-Agent Layer — Validation Suite")
    print("=" * 60)

    SECRET_AB = "secret-agent-a-b"

    # =====================================================================
    print("\n-- T01: Fresh message, valid HMAC, valid timestamp, fresh nonce → ALLOW --")
    payload = create_signed_payload("agent-a", "agent-b", "web_search", {"q": "hello"}, SECRET_AB)
    result = verify_message(payload, SECRET_AB)
    record("Fresh message ALLOWS", result == VerifyResult.ALLOW, f"Got: {result}")

    # =====================================================================
    print("\n-- T02: Replayed message (same nonce) → REPLAY_DETECTED --")
    # Re-send exact same payload (same nonce)
    result2 = verify_message(payload, SECRET_AB)
    record("Replayed nonce BLOCKED", result2 == VerifyResult.REPLAY_DETECTED, f"Got: {result2}")

    # =====================================================================
    print("\n-- T03: Expired timestamp (6 min old) → REPLAY_EXPIRED --")
    old_payload = create_signed_payload("agent-a", "agent-b", "test", {}, SECRET_AB)
    old_payload.pop("signature")
    old_payload["timestamp"] = int(time.time()) - 400  # 6+ min ago
    import hashlib, hmac as hmac_mod, json
    sig_input = json.dumps(old_payload, sort_keys=True)
    old_payload["signature"] = hmac_mod.new(SECRET_AB.encode(), sig_input.encode(), hashlib.sha256).hexdigest()
    result3 = verify_message(old_payload, SECRET_AB)
    record("Expired timestamp BLOCKED", result3 == VerifyResult.REPLAY_EXPIRED, f"Got: {result3}")

    # =====================================================================
    print("\n-- T04: Tampered message body, valid old signature → TAMPERED --")
    payload4 = create_signed_payload("agent-a", "agent-b", "safe_action", {"data": "original"}, SECRET_AB)
    payload4["body"] = {"data": "TAMPERED!"}  # Modify body after signing
    result4 = verify_message(payload4, SECRET_AB)
    record("Tampered message BLOCKED", result4 == VerifyResult.TAMPERED, f"Got: {result4}")

    # =====================================================================
    print("\n-- T05: Delegation cert depth=2 (max=3), action in scope → ALLOW --")
    cert5 = create_delegation("agent-a", "agent-b", ["web_search", "file_read"], SECRET_AB, max_depth=3)
    cert5.current_depth = 2
    cert5.sign(SECRET_AB)  # Re-sign after depth change
    result5 = verify_delegated_action("web_search", cert5, SECRET_AB)
    record("Valid delegation ALLOWS", result5 == VerifyResult.ALLOW, f"Got: {result5}")

    # =====================================================================
    print("\n-- T06: Delegation cert depth=4 (exceeds max=3) → DEPTH_EXCEEDED --")
    cert6 = create_delegation("agent-a", "agent-b", ["web_search"], SECRET_AB, max_depth=3)
    cert6.current_depth = 4
    cert6.sign(SECRET_AB)
    result6 = verify_delegated_action("web_search", cert6, SECRET_AB)
    record("Depth exceeded BLOCKED", result6 == VerifyResult.DELEGATION_DEPTH_EXCEEDED, f"Got: {result6}")

    # =====================================================================
    print("\n-- T07: Action not in delegation cert scope → SCOPE_VIOLATION --")
    cert7 = create_delegation("agent-a", "agent-b", ["web_search"], SECRET_AB)
    result7 = verify_delegated_action("db_query", cert7, SECRET_AB)
    record("Out-of-scope BLOCKED", result7 == VerifyResult.SCOPE_VIOLATION, f"Got: {result7}")

    # =====================================================================
    print("\n-- T08: Expired delegation cert → DELEGATION_EXPIRED --")
    cert8 = create_delegation("agent-a", "agent-b", ["web_search"], SECRET_AB, ttl_seconds=0)
    cert8.expires_at = time.time() - 10  # Already expired
    cert8.sign(SECRET_AB)
    result8 = verify_delegated_action("web_search", cert8, SECRET_AB)
    record("Expired cert BLOCKED", result8 == VerifyResult.DELEGATION_EXPIRED, f"Got: {result8}")

    # =====================================================================
    print("\n-- T09: Trust starts at 0.5, 3 verified messages → score > 0.5 --")
    ts = DirectedTrustStore()
    initial = ts.get_effective_trust("a", "b")
    record("Initial trust = 0.5", abs(initial - 0.5) < 0.01, f"Got: {initial}")
    ts.update_trust("a", "b", "MESSAGE_VERIFIED")  # +0.02
    ts.update_trust("a", "b", "MESSAGE_VERIFIED")  # +0.02
    ts.update_trust("a", "b", "MESSAGE_VERIFIED")  # +0.02
    after = ts.get_effective_trust("a", "b")
    record("Trust > 0.5 after 3 verified", after > 0.5, f"Got: {after:.3f}")

    # =====================================================================
    print("\n-- T10: Replay attack event → trust score drops by ~0.30 --")
    ts10 = DirectedTrustStore()
    before10 = ts10.get_effective_trust("a", "b")
    ts10.update_trust("a", "b", "REPLAY_DETECTED")  # -0.30
    after10 = ts10.get_effective_trust("a", "b")
    drop = before10 - after10
    record("Trust drops ~0.30 on replay", abs(drop - 0.30) < 0.05, f"Drop: {drop:.3f}")

    # =====================================================================
    print("\n-- T11: Trust score < 0.2 → all messages BLOCK --")
    l7 = L7InterAgentLayer(agent_id="receiver")
    sec = l7.register_peer("bad-agent")
    # Drive trust below 0.2
    l7.trust_store.update_trust("bad-agent", "receiver", "CERT_TAMPERED")   # -0.40 → ~0.10
    tier = l7.trust_store.get_trust_tier("bad-agent", "receiver")
    record("Low trust tier = BLOCK", tier == "BLOCK", f"Got: {tier}")

    msg11 = create_signed_payload("bad-agent", "receiver", "test", {}, sec)
    result11, evt11 = l7.verify_incoming(msg11)
    record("Low trust message BLOCKED", result11 == VerifyResult.BLOCKED_LOW_TRUST, f"Got: {result11}, evt: {evt11.message}")

    # =====================================================================
    print("\n-- T12: Trust decay after inactivity simulation --")
    ts12 = DirectedTrustStore()
    # Set initial trust
    ts12.update_trust("x", "y", "MESSAGE_VERIFIED")  # 0.5 + 0.02 = 0.52
    rec = ts12.get_record("x", "y")
    # Simulate 1hr inactivity
    rec.last_interaction = time.time() - 3600
    effective = ts12.get_effective_trust("x", "y")
    # After 1hr: 0.52 * (0.98^1) ≈ 0.5096
    record("Decay applied after 1hr", effective < 0.52, f"Got: {effective:.4f} (should be < 0.52)")

    # =====================================================================
    print("\n-- T13: Anomaly score = 0.0 for consistent action pattern --")
    bb = BehavioralBaseline()
    for _ in range(10):
        bb.record("peer-c", "file_read")
    score13 = bb.anomaly_score("peer-c", "file_read")
    record("Consistent pattern → 0.0", score13 == 0.0, f"Got: {score13}")

    # =====================================================================
    print("\n-- T14: Anomaly score > 0.9 for sudden category shift → BLOCK --")
    bb14 = BehavioralBaseline()
    for _ in range(10):
        bb14.record("peer-d", "file_read")  # all "read" category
    score14 = bb14.anomaly_score("peer-d", "execute_command")  # "system" category
    record("Sudden shift → anomaly > 0.9", score14 > 0.9, f"Got: {score14}")

    # Full pipeline test: anomaly > 0.9 should BLOCK
    l7_14 = L7InterAgentLayer(agent_id="receiver2")
    sec14 = l7_14.register_peer("shifty-agent")
    for _ in range(10):
        l7_14.behavioral_baseline.record("shifty-agent", "file_read")
    msg14 = create_signed_payload("shifty-agent", "receiver2", "execute_command", {}, sec14)
    result14, evt14 = l7_14.verify_incoming(msg14)
    record("Anomaly BLOCK in pipeline", result14 == VerifyResult.ANOMALY_BLOCKED, f"Got: {result14}, msg: {evt14.message}")

    # =====================================================================
    print("\n-- T15: Nonce registry at limit → expired flushed, message accepted --")
    nr = NonceRegistry()
    # Fill with expired nonces
    for i in range(10001):
        nr._nonces[f"old-nonce-{i}"] = time.time() - 1  # Already expired
    # New nonce should succeed after sweep
    ok = nr.check_and_register("fresh-nonce-abc")
    record("Fresh nonce accepted after sweep", ok, f"Got: {ok}, registry size: {nr.size}")

    # =====================================================================
    elapsed = time.time()
    print("\n" + "=" * 60)
    passed = sum(1 for _, p, _ in results if p)
    total = len(results)
    failed = total - passed

    if failed == 0:
        print(f"\033[92mAll {total} checks passed\033[0m")
    else:
        print(f"\033[91m{failed}/{total} checks FAILED\033[0m")
        print("\nFailed checks:")
        for name, p, detail in results:
            if not p:
                print(f"  x {name}: {detail}")

    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
