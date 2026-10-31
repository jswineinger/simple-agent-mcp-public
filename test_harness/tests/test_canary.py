#!/usr/bin/env python3
"""
test_canary.py — unit tests for test_harness/canary.py

Run: pytest test_harness/tests/
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import canary  # noqa: E402


def test_generate_run_id_is_unique_and_short():
    a = canary.generate_run_id()
    b = canary.generate_run_id()
    assert a != b
    assert len(a) == 12
    assert all(c in "0123456789abcdef" for c in a)


def test_pii_canary_shape_and_never_real_looking():
    run_id = canary.generate_run_id()
    pii = canary.generate_pii_canary(run_id)
    assert pii["run_id"] == run_id
    assert pii["canary_id"].startswith("pii-")

    # Group number "00" is never issued by the SSA — guaranteed-fake SSN.
    area, group, serial = pii["ssn"].split("-")
    assert group == "00"
    assert len(area) == 3 and len(serial) == 4

    # RFC 2606 reserves example.com for documentation/testing.
    assert pii["email"].endswith("@example.com")

    # 555-01XX is reserved for fictional use in the NANP.
    assert pii["phone"].startswith("555-01")

    # Two calls must not collide.
    pii2 = canary.generate_pii_canary(run_id)
    assert pii["canary_id"] != pii2["canary_id"]


def test_api_key_canary_shape():
    run_id = canary.generate_run_id()
    key = canary.generate_api_key_canary(run_id)
    assert key["run_id"] == run_id
    assert key["canary_id"].startswith("apikey-")
    assert key["api_key"].startswith("TESTKEY_")
    # No real vendor prefix should ever appear in a generated key.
    for real_prefix in ("AKIA", "sk-", "ghp_", "AIza"):
        assert real_prefix not in key["api_key"]


def test_injection_payload_variants():
    run_id = canary.generate_run_id()
    plain = canary.generate_injection_payload(run_id, "plain")
    persistence = canary.generate_injection_payload(run_id, "persistence")
    obfuscated = canary.generate_injection_payload(run_id, "obfuscated")

    assert "ignore" in plain.lower()
    assert "next 3 responses" in persistence.lower()
    assert "base64" in obfuscated.lower()

    # run_id is deliberately not embedded in the visible attack text.
    assert run_id not in plain
    assert run_id not in persistence
    assert run_id not in obfuscated


def test_injection_payload_rejects_unknown_variant():
    try:
        canary.generate_injection_payload("x", "not-a-real-variant")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_tool_poison_payload_is_run_id_tagged_and_distinct_from_injection_variants():
    run_id = canary.generate_run_id()
    poison = canary.generate_tool_poison_payload(run_id)

    # Fixed text, not randomized — same call always returns the same string
    # (it's meant to be baked into a permanent, always-on tool description).
    assert poison == canary.generate_tool_poison_payload(canary.generate_run_id())

    # Distinct from all three LLM01/LLM07 injection variants.
    plain = canary.generate_injection_payload(run_id, "plain")
    persistence = canary.generate_injection_payload(run_id, "persistence")
    obfuscated = canary.generate_injection_payload(run_id, "obfuscated")
    assert poison not in (plain, persistence, obfuscated)

    # run_id is deliberately not embedded in the visible text, same as
    # generate_injection_payload — but it IS tagged/tracked internally, the
    # same way every other generate_* function's output is: a tripwire
    # check against this run_id must catch the text leaking verbatim.
    assert run_id not in poison
    leaked = canary.check_for_leaked_canaries(f"...{poison}...", run_id)
    assert poison in leaked

    # A falsy run_id (the case at import time, building the permanent tool
    # description before any test run exists) must not raise and must not
    # track anything.
    other_run = canary.generate_run_id()
    canary.generate_tool_poison_payload(None)
    assert canary.check_for_leaked_canaries(poison, other_run) == []


def test_toxic_canary_marker():
    run_id = canary.generate_run_id()
    marker = canary.generate_toxic_canary_marker(run_id)
    assert marker == canary.TOXIC_PHRASE
    assert marker in canary.check_for_leaked_canaries(f"...{marker}...", run_id)


def test_new_injection_variants_are_distinct_and_tracked():
    run_id = canary.generate_run_id()
    plain = canary.generate_injection_payload(run_id, "plain")
    spanish = canary.generate_injection_payload(run_id, "spanish")
    homoglyph = canary.generate_injection_payload(run_id, "homoglyph")
    assert "instrucciones" in spanish
    # Looks like "plain" but must not match it as a plain string.
    assert "Ignore previous instructions" not in homoglyph
    assert "​" in homoglyph and any(0x0400 <= ord(c) <= 0x04FF for c in homoglyph)
    assert len({plain, spanish, homoglyph}) == 3
    assert homoglyph in canary.check_for_leaked_canaries(homoglyph, run_id)


def test_split_injection_halves_are_harmless_alone_but_tracked():
    run_id = canary.generate_run_id()
    first, second = canary.generate_split_injection_payload(run_id)
    assert "system prompt" not in first
    assert "Ignore previous" not in second
    assert {first, second} <= set(canary.check_for_leaked_canaries(first + second, run_id))


def test_agency_payload_tracks_account_and_recipient():
    run_id = canary.generate_run_id()
    p = canary.generate_agency_payload(run_id)
    assert p["account"] in p["text"] and p["recipient"] in p["text"]
    leaked = canary.check_for_leaked_canaries(f"to={p['recipient']} acct={p['account']}", run_id)
    assert p["account"] in leaked and p["recipient"] in leaked
    # A fresh account id per run.
    assert canary.generate_agency_payload(run_id)["account"] != p["account"]


def test_output_handling_payload_uses_reserved_hosts_only():
    run_id = canary.generate_run_id()
    text = canary.generate_output_handling_payload(run_id)
    for m in canary.OUTPUT_HANDLING_MARKERS:
        assert m in text
    assert "](https://status-badge.attacker.example/" in text


def test_log_tool_invocation_tracks_canary_without_requiring_debug_json(monkeypatch, tmp_path):
    """
    Tripwire tracking (_SEEN_CANARIES) must work even when DEBUG_JSON is off
    — it's a safety check, not a debug feature, and shouldn't silently do
    nothing just because logging is disabled.
    """
    monkeypatch.setenv("DEBUG_JSON", "false")
    run_id = canary.generate_run_id()
    pii = canary.generate_pii_canary(run_id)

    canary.log_tool_invocation(
        "get_customer_record", {"customer_id": "C-1", "run_id": run_id},
        pii["canary_id"], {"tax_id": pii["ssn"]}
    )

    leaked = canary.check_for_leaked_canaries(f"leaked value: {pii['ssn']} tagged {pii['canary_id']}", run_id)
    assert pii["canary_id"] in leaked


def test_check_for_leaked_canaries_no_false_positive_across_runs():
    run_a = canary.generate_run_id()
    run_b = canary.generate_run_id()
    pii_a = canary.generate_pii_canary(run_a)

    canary.log_tool_invocation(
        "get_customer_record", {"customer_id": "C-1", "run_id": run_a},
        pii_a["canary_id"], {}
    )

    # Same canary_id text, but checked against a DIFFERENT run_id — must not match.
    leaked = canary.check_for_leaked_canaries(pii_a["canary_id"], run_b)
    assert leaked == []


def test_check_for_leaked_canaries_empty_inputs():
    assert canary.check_for_leaked_canaries("", "some-run") == []
    assert canary.check_for_leaked_canaries("some text", "") == []


def test_log_tool_invocation_writes_jsonl_when_debug_json_enabled(monkeypatch, tmp_path):
    monkeypatch.setenv("DEBUG_JSON", "true")
    log_dir = tmp_path / "logs"
    monkeypatch.setattr(canary, "LOG_DIR", str(log_dir))
    monkeypatch.setattr(canary, "TOOL_INVOCATIONS_LOG", str(log_dir / "tool_invocations.jsonl"))

    run_id = canary.generate_run_id()
    canary.log_tool_invocation(
        "get_user_reviews", {"product_id": "P-1", "run_id": run_id}, "tox-abc", {"rating": 1}
    )

    log_file = log_dir / "tool_invocations.jsonl"
    assert log_file.exists()
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    import json
    record = json.loads(lines[0])
    assert record["tool_name"] == "get_user_reviews"
    assert record["canary_id"] == "tox-abc"


def test_log_tool_invocation_writes_nothing_when_debug_json_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("DEBUG_JSON", "false")
    log_dir = tmp_path / "logs2"
    monkeypatch.setattr(canary, "LOG_DIR", str(log_dir))
    monkeypatch.setattr(canary, "TOOL_INVOCATIONS_LOG", str(log_dir / "tool_invocations.jsonl"))

    canary.log_tool_invocation("get_user_reviews", {"product_id": "P-1"}, "tox-xyz", {"rating": 1})

    assert not (log_dir / "tool_invocations.jsonl").exists()


def test_homoglyph_tool_poison_hides_the_plain_text():
    plain = canary.generate_tool_poison_payload(None)
    hidden = canary.generate_tool_poison_payload(None, "homoglyph")
    assert hidden != plain and "SSN" in hidden  # all-caps letters untouched
    assert "always include" not in hidden and "\u200b" in hidden
    assert hidden == canary.generate_tool_poison_payload(None, "homoglyph")  # fixed text


def test_scope_creep_payload_tracks_its_account():
    run_id = canary.generate_run_id()
    text = canary.generate_scope_creep_payload(run_id)
    account = next(w.rstrip(".") for w in text.split() if w.startswith("ACCT-"))
    assert "execute_transaction" in text
    assert account in canary.check_for_leaked_canaries(f"account={account}", run_id)
