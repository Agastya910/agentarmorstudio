"""L2 Storage Layer Validation Suite — Real cryptographic tests against studio.db"""
import sys
import io
import sqlite3
import json
import os
import time
from pathlib import Path

# Fix Windows cp1252 encoding crash on emoji chars
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Ensure agentarmor package is importable from source
sys.path.insert(0, str(Path(r"c:\Users\agast\Downloads\agentarmor\src")))

from agentarmor.crypto.keys import AGENTARMOR_DIR, get_db_key, get_api_key_key, get_or_create_master_key
from agentarmor.crypto.encryption import encrypt_field, decrypt_field, is_encrypted, compute_mac, verify_mac

STUDIO_DB_PATH = AGENTARMOR_DIR / "studio.db"

# Now import StudioDB (it also needs agentarmor on path, which we set above)
from studio_db import StudioDB


def run_l2_validation():
    print("=" * 60)
    print("  L2 STORAGE ENCRYPTION VALIDATION SUITE")
    print("=" * 60)

    # ── Pre-check: Key Infrastructure ─────────────────────────────
    print("\n[0] Key Infrastructure Check...")
    salt_path = AGENTARMOR_DIR / "install.salt"
    t0 = time.perf_counter()
    master = get_or_create_master_key()
    t1 = time.perf_counter()
    print(f"  Master key derived in {(t1-t0)*1000:.1f}ms")
    print(f"  install.salt exists: {salt_path.exists()}")
    print(f"  install.salt size: {salt_path.stat().st_size} bytes")
    print(f"  Master key length: {len(master)} bytes")
    db_key = get_db_key()
    api_key = get_api_key_key()
    print(f"  DB child key length: {len(db_key)} bytes")
    print(f"  API child key length: {len(api_key)} bytes")
    print(f"  Keys are different: {db_key != api_key}")
    if len(master) == 32 and salt_path.exists() and db_key != api_key:
        print("  -> PASS: Key hierarchy operational ✅")
    else:
        print("  -> FAIL ❌")

    # ── Initialize DB ─────────────────────────────────────────────
    db = StudioDB(STUDIO_DB_PATH)

    # Direct SQLite connection for raw reads (bypassing decryption)
    conn = sqlite3.connect(str(STUDIO_DB_PATH))
    conn.row_factory = sqlite3.Row

    # ── Test 1: Settings Encryption (Sub-Task C) ─────────────────
    print("\n[1] Settings API Key Encryption (Sub-Task C)...")
    db.set_setting("test_api_key", "sk-LIVE-1234567890abcdef")

    row = conn.execute("SELECT value FROM settings WHERE key='test_api_key'").fetchone()
    raw_val = row["value"]
    print(f"  Raw SQLite value: {raw_val[:50]}...")
    assert raw_val.startswith("AA2:"), "FAIL: Setting stored as plaintext!"
    print("  -> PASS: Setting is AES-256-GCM encrypted (AA2: prefix) ✅")

    decrypted_val = db.get_setting("test_api_key")
    assert decrypted_val == "sk-LIVE-1234567890abcdef", f"FAIL: Decrypted value mismatch: {decrypted_val}"
    print(f"  Decrypted value: {decrypted_val}")
    print("  -> PASS: Round-trip encrypt/decrypt verified ✅")

    # ── Test 2: Message Encryption (Sub-Task D) ──────────────────
    print("\n[2] Conversation Message Encryption (Sub-Task D)...")
    conv_id = db.create_conversation("studio", "L2 Validation Chat")
    msg_id = db.append_message(conv_id, "user", "My secret password is hunter2")

    msg_row = conn.execute("SELECT content, tool_calls, _mac FROM messages WHERE id=?", (msg_id,)).fetchone()
    raw_content = msg_row["content"]
    raw_mac = msg_row["_mac"]
    print(f"  Raw SQLite content: {raw_content[:50]}...")
    print(f"  HMAC-SHA256 MAC: {raw_mac}")
    assert raw_content.startswith("AA2:"), "FAIL: Message content stored as plaintext!"
    print("  -> PASS: Message content is AES-256-GCM encrypted ✅")
    assert raw_mac and len(raw_mac) == 64, "FAIL: MAC not computed!"
    print("  -> PASS: HMAC-SHA256 integrity MAC stored ✅")

    msgs = db.get_messages(conv_id)
    assert msgs[0]["content"] == "My secret password is hunter2", f"FAIL: Decrypted mismatch: {msgs[0]['content']}"
    print(f"  Decrypted content: {msgs[0]['content']}")
    print("  -> PASS: Message round-trip decrypt verified ✅")

    # ── Test 3: Event Details Encryption (Sub-Task E) ─────────────
    print("\n[3] Security Event Details Encryption (Sub-Task E)...")
    test_event = {
        "event_id": "test-l2-001",
        "agent_id": "studio",
        "layer": "L1_ingestion",
        "event_type": "test",
        "action": "scan",
        "verdict": "deny",
        "threat_level": "high",
        "message": "L2 validation test event",
        "details": {"matched_pattern": "system_override", "input_preview": "ignore previous instructions"},
        "tool_name": "",
        "tool_args": {},
        "latency_ms": 1.5,
    }
    db.store_event(test_event)

    evt_row = conn.execute("SELECT details, _mac FROM events WHERE event_id='test-l2-001'").fetchone()
    raw_details = evt_row["details"]
    evt_mac = evt_row["_mac"]
    print(f"  Raw SQLite details: {raw_details[:50]}...")
    print(f"  Event MAC: {evt_mac}")
    assert raw_details.startswith("AA2:"), "FAIL: Event details stored as plaintext!"
    print("  -> PASS: Event details are AES-256-GCM encrypted ✅")
    assert evt_mac and len(evt_mac) == 64, "FAIL: Event MAC not computed!"
    print("  -> PASS: Event HMAC integrity MAC stored ✅")

    events = db.get_events(limit=1, agent_id="studio")
    found = [e for e in events if e.get("event_id") == "test-l2-001"]
    if found:
        print(f"  Decrypted details: {json.dumps(found[0]['details'], indent=2)}")
        print("  -> PASS: Event details round-trip decrypt verified ✅")

    # ── Test 4: Tamper Detection (HMAC + AES-GCM Auth Tag) ────────
    print("\n[4] L2 Tamper Detection (Memory Poisoning Defense)...")
    print("  Simulating attacker: directly editing message ciphertext in SQLite...")

    tampered = raw_content[:-2] + ('XX')
    conn.execute("UPDATE messages SET content=? WHERE id=?", (tampered, msg_id))
    conn.commit()

    msgs_tampered = db.get_messages(conv_id)
    tampered_result = msgs_tampered[0]["content"]
    print(f"  Result after tamper: {tampered_result[:80]}...")

    if "L2 Tamper Alert" in tampered_result or "Corrupted" in tampered_result:
        print("  -> PASS: Tamper Alert triggered! AES-GCM auth failed + MAC mismatch ✅")
    else:
        print(f"  -> FAIL: Tamper not detected! Got: {tampered_result}")

    # ── Test 5: Performance Budget ────────────────────────────────
    print("\n[5] Latency Budget Check...")
    test_str = "Performance test string for encryption latency measurement"
    key = get_db_key()

    # Encrypt
    t0 = time.perf_counter()
    for _ in range(100):
        enc = encrypt_field(test_str, key)
    t1 = time.perf_counter()
    enc_ms = (t1 - t0) / 100 * 1000
    print(f"  encrypt_field avg: {enc_ms:.3f}ms (target: <1ms)")

    # Decrypt
    t0 = time.perf_counter()
    for _ in range(100):
        dec = decrypt_field(enc, key)
    t1 = time.perf_counter()
    dec_ms = (t1 - t0) / 100 * 1000
    print(f"  decrypt_field avg: {dec_ms:.3f}ms (target: <1ms)")

    # MAC
    mac_data = {"test": "data", "key": "value"}
    t0 = time.perf_counter()
    for _ in range(100):
        compute_mac(mac_data, key)
    t1 = time.perf_counter()
    mac_ms = (t1 - t0) / 100 * 1000
    print(f"  compute_mac avg: {mac_ms:.3f}ms (target: <0.5ms)")

    if enc_ms < 1.0 and dec_ms < 1.0 and mac_ms < 0.5:
        print("  -> PASS: All operations within latency budget ✅")
    else:
        print("  -> WARN: Some operations exceeded budget ⚠️")

    # ── Cleanup ───────────────────────────────────────────────────
    db.delete_conversation(conv_id)
    conn.execute("DELETE FROM settings WHERE key='test_api_key'")
    conn.execute("DELETE FROM events WHERE event_id='test-l2-001'")
    conn.commit()
    conn.close()

    print("\n" + "=" * 60)
    print("  L2 VALIDATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    run_l2_validation()
