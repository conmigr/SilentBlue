"""Session cost ledger groups work and models."""

from silentblue.ledger import SessionLedger
from silentblue.model import ModelReply


def test_cost_matrix_keeps_scan_assess_and_nlp_apart():
    ledger = SessionLedger()
    ledger.note_scan("scan")
    ledger.add("assess", ModelReply("review", 100, 20, 5), "grok", "grok-4.7")
    ledger.add("nlp", ModelReply("route", 40, 8, None), "openai", "gpt-6.1-terra")
    text = "\n".join(ledger.render())
    assert "Total USD: 0.0004" in text
    assert "Model calls: 2" in text
    assert "scan: 0.0000 USD, calls 0, in 0, out 0, thinking 0" in text
    assert "assess: 0.0003 USD, calls 1, in 100, out 20, thinking 5" in text
    assert "nlp: 0.0001 USD, calls 1, in 40, out 8, thinking unknown" in text
    assert "grok grok-4.7: 0.0003 USD, calls 1, in 100, out 20, thinking 5" in text
    assert "openai gpt-6.1-terra: 0.0001 USD, calls 1, in 40, out 8, thinking unknown" in text
    assert "Work: assess" in text
    assert "Work: nlp" in text
    assert "Model: none" in text


def test_a_missing_token_count_leaves_that_cost_unknown():
    ledger = SessionLedger()
    ledger.add("threat-model", "not usage", "grok", "grok-4.7")
    text = "\n".join(ledger.render())
    assert "Total USD: unknown" in text
    assert "threat-model: unknown USD, calls 1, in unknown, out unknown, thinking unknown" in text
