"""Local end-to-end test: real HTTP requests to a running rules-validator.

Skips automatically unless a rules-validator is reachable at
RULES_VALIDATOR_URL (default http://localhost:8080/v1/rules/validate), so
plain `pytest` stays green with no infra. `make e2e-local` builds and runs a
real rules-validator container and then runs this file against it.
"""
import os

import pytest
import requests

from waf_rule_mpc.tools import (
    RulesValidator,
    RULE_TYPE_WAF,
    RULE_TYPE_SMART_FIREWALL,
)

RULES_VALIDATOR_URL = os.getenv(
    "RULES_VALIDATOR_URL", "http://localhost:8080/v1/rules/validate"
)


def _reachable(url: str) -> bool:
    try:
        # A well-formed minimal request; any HTTP response means it's up.
        requests.post(url, json={"expression": "ip.src eq 1.2.3.4",
                                 "rule_type": "waf"}, timeout=3)
        return True
    except requests.exceptions.RequestException:
        return False


pytestmark = pytest.mark.skipif(
    not _reachable(RULES_VALIDATOR_URL),
    reason=f"rules-validator not reachable at {RULES_VALIDATOR_URL} "
           f"(run `make e2e-local`)",
)


@pytest.fixture(scope="module")
def validator():
    return RulesValidator(RULES_VALIDATOR_URL)


def test_waf_valid_expression(validator):
    out = validator.validate_expression(
        'http.request.path eq "/login"', RULE_TYPE_WAF
    )
    assert out["valid"] is True, out


def test_waf_invalid_expression(validator):
    out = validator.validate_expression("totally not valid (((", RULE_TYPE_WAF)
    assert out["valid"] is False
    assert out.get("error_message")


def test_smart_firewall_valid_l3l4_expression(validator):
    out = validator.validate_expression(
        "ip.src in {192.0.2.0/24}", RULE_TYPE_SMART_FIREWALL
    )
    assert out["valid"] is True, out


def test_smart_firewall_rejects_http_fields(validator):
    # The key Smart Firewall guarantee: the L3/L4 scheme has no http.*
    # fields, so a WAF-style expression must fail for smart_firewall.
    out = validator.validate_expression(
        'http.request.path eq "/login"', RULE_TYPE_SMART_FIREWALL
    )
    assert out["valid"] is False
    assert out.get("error_message")


def test_waf_with_test_match(validator):
    out = validator.validate_expression(
        'http.request.path eq "/admin"',
        RULE_TYPE_WAF,
        test_data={"http.request.path": "/admin"},
    )
    assert out["valid"] is True, out
    assert "matched" in out


def test_test_expression_uses_mock_data(validator):
    out = validator.test_expression(
        'http.request.method eq "POST"', RULE_TYPE_WAF
    )
    assert out["valid"] is True, out
    assert "matched" in out
