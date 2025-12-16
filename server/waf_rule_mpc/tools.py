import requests
import logging

logger = logging.getLogger(__name__)

class WAFValidator:

    def __init__(self, validation_url: str):
        self.validation_url = validation_url
        # Use a session to maintain cookies across requests (helps with session management)
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "gen0sec-mcp-server/1.0"
        })

    def _api_request(self, payload: dict) -> dict:
        """
        Make a POST request to the WAF validation API with the given payload.

        Args:
            payload (dict): The payload to send in the POST request.

        Returns:
            dict: The JSON response from the API.
        """
        try:
            # Use session to maintain cookies and headers across requests
            response = self.session.post(self.validation_url, json=payload)
            print(payload)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            # Try to extract error message from response body
            error_msg = f"Error POSTing to endpoint (HTTP {response.status_code})"
            try:
                error_body = response.json()
                if isinstance(error_body, dict):
                    # Try common error message fields
                    api_error = error_body.get("error") or error_body.get("error_message") or error_body.get("message")
                    if api_error:
                        error_msg = f"{error_msg}: {api_error}"
                    else:
                        # Fallback to full response if no standard error field
                        error_msg = f"{error_msg}: {response.text[:200]}"
                else:
                    error_msg = f"{error_msg}: {response.text[:200]}"
            except (ValueError, AttributeError):
                # If response is not JSON, use status text
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

    def validate_waf_expression(self, expression: str, test_data: dict = None) -> str:
        """
        Validates a WAF expression through the WAF validation API.

        Args:
            expression (str): The WAF expression to validate.
            test_data (dict, optional): Optional custom test data to use for matching.
                                       If provided, test_match will be set to True.

        Returns:
            str: The result of the validation.
        """
        payload = {
            "expression": expression,
            "test_match": test_data is not None and len(test_data) > 0
        }

        # Add custom test data if provided
        if test_data is not None and len(test_data) > 0:
            payload["test"] = test_data

        response = self._api_request(payload)

        # Check if API request itself failed
        if "error" in response:
            return {
                "valid": False,
                "error_message": response["error"]
            }

        result = {
            "valid": response.get("valid", False)
        }
        if not result["valid"]:
            result["error_message"] = response.get("error_message", response.get("error", "Unknown error"))

        # Include test result if test_match was True
        if payload["test_match"]:
            result["matched"] = response.get("test_result", {}).get("matched", False)
            if response.get("test_result", {}).get("error"):
                result["test_error"] = response.get("test_result", {}).get("error", "Unknown error")

        return result

    def test_waf_expression(self, expression: str, test_data: dict = None) -> dict:
        """
        Tests a WAF expression against provided test data through the WAF validation API.

        Args:
            expression (str): The WAF expression to test.
            test_data (dict, optional): The custom test data to use for matching.
                                       If not provided, uses default mock data.

        Returns:
            dict: The result of the test including match information.
        """
        payload = {
            "expression": expression,
            "test_match": True
        }

        # Add custom test data if provided
        if test_data is not None and len(test_data) > 0:
            payload["test"] = test_data

        response = self._api_request(payload)

        # Check if API request itself failed
        if "error" in response:
            return {
                "valid": False,
                "matched": False,
                "error": response["error"]
            }

        result = {
            "valid": response.get("valid", False),
            "matched": response.get("test_result", {}).get("matched", False)
        }
        if not result["valid"]:
            result["error"] = response.get("error_message", response.get("error", "Unknown error"))
        if response.get("test_result", {}).get("error"):
            result["test_error"] = response.get("test_result", {}).get("error", "Unknown error")

        return result
