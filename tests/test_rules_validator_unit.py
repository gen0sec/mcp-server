"""Unit tests for RulesValidator that need no network (always run)."""
import pytest

from waf_rule_mpc.tools import (
    RulesValidator,
    WAFValidator,
    RULE_TYPE_WAF,
    RULE_TYPE_SMART_FIREWALL,
)


def test_backward_compatible_alias():
    assert WAFValidator is RulesValidator


@pytest.mark.parametrize(
    "given,expected",
    [
        ("waf", RULE_TYPE_WAF),
        ("WAF", RULE_TYPE_WAF),
        (" smart_firewall ", RULE_TYPE_SMART_FIREWALL),
        (None, RULE_TYPE_WAF),
        ("", RULE_TYPE_WAF),
    ],
)
def test_normalize_rule_type_ok(given, expected):
    assert RulesValidator._normalize_rule_type(given) == expected


def test_normalize_rule_type_rejects_unknown():
    with pytest.raises(ValueError):
        RulesValidator._normalize_rule_type("ids")


def test_transport_error_returns_clean_dict():
    # Nothing listening on this port -> connection error, no exception raised.
    v = RulesValidator("http://127.0.0.1:1/v1/rules/validate")
    out = v.validate_expression("ip.src eq 1.2.3.4", RULE_TYPE_WAF)
    assert out["valid"] is False
    assert "error_message" in out
