import requests
import logging

logger = logging.getLogger(__name__)

# Rule types understood by the rules-validator API. Selects the Wirefilter
# scheme: "waf" (HTTP L7 fields) or "smart_firewall" (L3/L4 + JA4, no http.*).
RULE_TYPE_WAF = "waf"
RULE_TYPE_SMART_FIREWALL = "smart_firewall"
VALID_RULE_TYPES = (RULE_TYPE_WAF, RULE_TYPE_SMART_FIREWALL)


class RulesValidator:
    """Client for the gen0sec rules-validator API (POST /v1/rules/validate).

    Validates Wirefilter expressions for both WAF and Smart Firewall rules;
    the scheme is selected per request via ``rule_type``.
    """

    def __init__(self, validation_url: str):
        self.validation_url = validation_url
        # Use a session to keep connection/headers across requests.
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "gen0sec-mcp-server/1.0"
        })

    @staticmethod
    def _normalize_rule_type(rule_type: str) -> str:
        rt = (rule_type or RULE_TYPE_WAF).strip().lower()
        if rt not in VALID_RULE_TYPES:
            raise ValueError(
                f"invalid rule_type {rule_type!r}; expected one of {VALID_RULE_TYPES}"
            )
        return rt

    def _api_request(self, payload: dict) -> dict:
        """POST the payload to the rules-validator API and return the JSON.

        On any transport/HTTP error returns ``{"error": ..., "valid": False}``
        so callers can surface a clean message instead of raising.
        """
        try:
            response = self.session.post(self.validation_url, json=payload)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            error_msg = f"Error POSTing to endpoint (HTTP {response.status_code})"
            try:
                error_body = response.json()
                if isinstance(error_body, dict):
                    api_error = (
                        error_body.get("error")
                        or error_body.get("error_message")
                        or error_body.get("message")
                    )
                    if api_error:
                        error_msg = f"{error_msg}: {api_error}"
                    else:
                        error_msg = f"{error_msg}: {response.text[:200]}"
                else:
                    error_msg = f"{error_msg}: {response.text[:200]}"
            except (ValueError, AttributeError):
                error_msg = f"{error_msg}: {response.reason or str(e)}"

            logger.error(error_msg)
            return {"error": error_msg, "valid": False}
        except requests.exceptions.RequestException as e:
            error_msg = f"Error POSTing to endpoint: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg, "valid": False}
        except Exception as e:
            error_msg = f"Unexpected error during API request: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg, "valid": False}

    def validate_expression(
        self, expression: str, rule_type: str = RULE_TYPE_WAF, test_data: dict = None
    ) -> dict:
        """Validate a Wirefilter expression for the given rule type.

        Args:
            expression: The Wirefilter expression to validate.
            rule_type: "waf" (default) or "smart_firewall" — selects the
                Wirefilter scheme the expression is validated against.
            test_data: Optional custom test data; when provided the
                expression is also matched against it.

        Returns:
            ``{"valid": bool, "error_message"?: str, "matched"?: bool,
            "test_error"?: str}``
        """
        rule_type = self._normalize_rule_type(rule_type)
        has_test = test_data is not None and len(test_data) > 0
        payload = {
            "expression": expression,
            "rule_type": rule_type,
            "test_match": has_test,
        }
        if has_test:
            payload["test"] = test_data

        response = self._api_request(payload)

        if "error" in response:
            return {"valid": False, "error_message": response["error"]}

        result = {"valid": response.get("valid", False)}
        if not result["valid"]:
            result["error_message"] = response.get(
                "error_message", response.get("error", "Unknown error")
            )
        if has_test:
            test_result = response.get("test_result") or {}
            result["matched"] = test_result.get("matched", False)
            if test_result.get("error"):
                result["test_error"] = test_result.get("error", "Unknown error")
        return result

    def test_expression(
        self, expression: str, rule_type: str = RULE_TYPE_WAF, test_data: dict = None
    ) -> dict:
        """Validate and match an expression against test data (mock if none).

        Returns ``{"valid": bool, "matched": bool, "error"?: str,
        "test_error"?: str}``.
        """
        rule_type = self._normalize_rule_type(rule_type)
        payload = {
            "expression": expression,
            "rule_type": rule_type,
            "test_match": True,
        }
        if test_data is not None and len(test_data) > 0:
            payload["test"] = test_data

        response = self._api_request(payload)

        if "error" in response:
            return {"valid": False, "matched": False, "error": response["error"]}

        test_result = response.get("test_result") or {}
        result = {
            "valid": response.get("valid", False),
            "matched": test_result.get("matched", False),
        }
        if not result["valid"]:
            result["error"] = response.get(
                "error_message", response.get("error", "Unknown error")
            )
        if test_result.get("error"):
            result["test_error"] = test_result.get("error", "Unknown error")
        return result


# Backwards-compatible alias: the class was previously named WAFValidator and
# only handled WAF rules. Kept so any out-of-tree importers keep working.
WAFValidator = RulesValidator
