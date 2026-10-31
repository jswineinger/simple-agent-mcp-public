#!/usr/bin/env python3
"""
test_tools.py — one representative OWASP-harness tool per category,
exercised directly (no HTTP server needed — same style as the tool
handlers themselves: plain functions, no framework).

Run: pytest test_harness/tests/
"""

import logging
import os
import sys

import pytest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(TESTS_DIR, "..", "..", "mcp-server"))
sys.path.insert(0, os.path.join(TESTS_DIR, ".."))

import mcp_server  # noqa: E402
import canary  # noqa: E402


# --- DLP / Sensitive Information Disclosure (LLM02) --------------------

def test_get_customer_record_returns_legitimate_data_plus_canary():
    result = mcp_server.handle_get_customer_record("C-1029", run_id="run-dlp-1")
    # Legitimate-looking data alongside the canary, not just the canary alone.
    assert result["customer_id"] == "C-1029"
    assert result["name"]
    assert result["plan"]
    # The canary itself: a synthetic SSN in the guaranteed-fake "00" group.
    assert result["tax_id"].split("-")[1] == "00"
    assert result["contact_email"].endswith("@example.com")


# --- MCP03 / Tool Poisoning ----------------------------------------------

def test_get_customer_record_poisoned_returns_same_shape_as_clean_tool():
    clean = mcp_server.handle_get_customer_record("C-1029", run_id="run-poison-1")
    poisoned = mcp_server.handle_get_customer_record_poisoned("C-1029", run_id="run-poison-1")
    # Same mock data shape — the poison lives in the tool's registered
    # description (TOOLS), never in the returned data.
    assert set(clean.keys()) == set(poisoned.keys())
    assert poisoned["customer_id"] == "C-1029"
    assert poisoned["tax_id"].split("-")[1] == "00"
    assert poisoned["contact_email"].endswith("@example.com")


def test_get_customer_record_poisoned_tool_description_carries_hidden_payload():
    tool_names = {t["name"] for t in mcp_server.TOOLS}
    if "get_customer_record" not in tool_names or "get_customer_record_poisoned" not in tool_names:
        pytest.skip(
            "get_customer_record / get_customer_record_poisoned currently "
            "commented out of TOOLS (see mcp_server.py) — skipping until restored"
        )
    clean_tool = next(t for t in mcp_server.TOOLS if t["name"] == "get_customer_record")
    poisoned_tool = next(t for t in mcp_server.TOOLS if t["name"] == "get_customer_record_poisoned")

    poison_text = canary.generate_tool_poison_payload(None)
    assert poison_text in poisoned_tool["description"]
    # The clean tool's description must never carry it.
    assert poison_text not in clean_tool["description"]


# --- Prompt Injection / System Prompt Leakage (LLM01, LLM07) -----------

def test_read_email_embeds_injection_alongside_legitimate_content():
    result = mcp_server.handle_read_email("MSG-1", run_id="run-inj-1")
    assert result["from"]
    assert result["subject"]
    assert "ignore" in result["body"].lower()  # the injection variant used


@pytest.mark.parametrize("ticket_id", ["T-4481", "T-4482", "T-4483", "T-4484", "T-4485"])
def test_injection_variant_tickets_carry_payload_inside_legit_content(ticket_id):
    result = mcp_server.handle_get_support_ticket(ticket_id, run_id="run-var-1")
    assert result["ticket_id"] == ticket_id
    assert result["body"].startswith("Customer reports")
    plain = canary.generate_injection_payload("x", "plain")
    assert plain not in result["body"]  # each is a variant, not the original


def test_read_email_msg_8843_requests_unrequested_actions():
    result = mcp_server.handle_read_email("MSG-8843", run_id="run-agency-1")
    assert canary.AGENCY_RECIPIENT in result["body"]
    assert "ACCT-" in result["body"]


# --- Toxicity / Improper Output Handling (LLM05) ------------------------

def test_dilution_pairs_differ_only_by_surrounding_text():
    iso = mcp_server.handle_get_support_ticket("T-4491", run_id="run-dil-1")
    ctx = mcp_server.handle_get_support_ticket("T-4492", run_id="run-dil-1")
    assert iso["body"] == f"Card on file: {canary.TEST_CARD}"
    assert ctx["body"].endswith(iso["body"]) and len(ctx["body"]) > len(iso["body"])
    assert set(iso) == {"ticket_id", "body"}  # nothing else to dilute it

    iso = mcp_server.handle_get_user_reviews("P-2211", run_id="run-dil-1")
    ctx = mcp_server.handle_get_user_reviews("P-2212", run_id="run-dil-1")
    assert [r["text"] for r in iso] == [canary.ABUSIVE_PHRASE]
    assert canary.ABUSIVE_PHRASE in [r["text"] for r in ctx] and len(ctx) == 3


def test_ticket_t4473_carries_output_handling_payload():
    result = mcp_server.handle_get_support_ticket("T-4473", run_id="run-out-1")
    assert all(m in result["body"] for m in canary.OUTPUT_HANDLING_MARKERS)


def test_get_user_reviews_embeds_toxic_marker_in_one_review_only():
    result = mcp_server.handle_get_user_reviews("P-1", run_id="run-tox-1")
    marker = canary.TOXIC_PHRASE
    matching = [r for r in result if marker in r["text"]]
    assert len(matching) == 1
    # Legitimate reviews present alongside it, not canary-only output.
    assert len(result) > 1


# --- Excessive Agency (LLM06) — tripwire ---------------------------------

def test_send_email_tripwire_fires_critical_on_leaked_canary(caplog):
    """
    Realistic scenario: leak the ACTUAL returned SSN value, not the
    internal canary_id label — canary_id is never returned to the LLM in
    the first place, so a test that only leaks canary_id wouldn't catch a
    tracking bug that only registers labels instead of real values.
    """
    run_id = "run-tripwire-1"
    record = mcp_server.handle_get_customer_record("C-1", run_id=run_id)

    with caplog.at_level(logging.CRITICAL, logger="mcp_server"):
        mcp_server.handle_send_email(
            "attacker@example.com", "data",
            f"here is the record: {record['tax_id']}", run_id=run_id
        )

    assert any("TRIPWIRE FIRED" in r.message for r in caplog.records)


def test_send_email_tripwire_silent_on_clean_content(caplog):
    run_id = "run-tripwire-2"
    with caplog.at_level(logging.CRITICAL, logger="mcp_server"):
        mcp_server.handle_send_email(
            "customer@example.com", "Your ticket update",
            "Thanks for reaching out, we've resolved your issue.", run_id=run_id
        )
    assert not any("TRIPWIRE FIRED" in r.message for r in caplog.records)


def test_send_email_is_safe_by_construction_no_real_side_effect():
    # No exception, no network, no state beyond the returned confirmation —
    # this is the whole point of the safe-by-construction design.
    result = mcp_server.handle_send_email("x@example.com", "s", "b", run_id="run-safe-1")
    assert result["status"] == "sent (simulated)"


# --- OWASP MCP Top 10 additions -------------------------------------------

def _tool(name):
    return next(t for t in mcp_server.TOOLS if t["name"] == name)


def test_mcp03_hidden_and_param_variants_carry_the_poison_where_named():
    plain = canary.generate_tool_poison_payload(None)
    hidden = _tool("get_customer_record_poisoned_hidden")
    assert canary.generate_tool_poison_payload(None, "homoglyph") in hidden["description"]
    assert plain not in hidden["description"]
    param = _tool("get_customer_record_poisoned_param")
    assert plain not in param["description"]
    assert plain in param["inputSchema"]["properties"]["customer_id"]["description"]
    for name in ("get_customer_record_poisoned_hidden", "get_customer_record_poisoned_param"):
        result = mcp_server.dispatch(name, {"customer_id": "C-1029", "run_id": "run-mcp03"})
        assert result["customer_id"] == "C-1029"


def test_mcp02_ticket_pushes_a_money_moving_call():
    result = mcp_server.handle_get_support_ticket("T-4474", run_id="run-mcp02")
    assert "execute_transaction" in result["body"] and "ACCT-" in result["body"]


def test_mcp06_vendor_notice_page_carries_visible_injection():
    resp = mcp_server.app.test_client().get("/lab/vendor-notice")
    assert resp.status_code == 200 and resp.mimetype == "text/html"
    assert canary.WEB_INJECTION in resp.get_data(as_text=True)


def test_mcp07_mcp_endpoint_rejects_missing_token():
    resp = mcp_server.app.test_client().post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert resp.status_code == 401
