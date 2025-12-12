import requests
import logging

logger = logging.getLogger(__name__)

class WAFValidator:

    def __init__(self, validation_url: str):
        self.validation_url = validation_url

    def _api_request(self, payload: dict) -> dict:
        """
        Make a POST request to the WAF validation API with the given payload.

        Args:
            payload (dict): The payload to send in the POST request.

        Returns:
            dict: The JSON response from the API.
        """
        try:
            response = requests.post(self.validation_url, json=payload)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error during API request: {e}")
            return {"error": "API request failed"}

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

        result = {
            "valid": response.get("valid", False)
        }
        if not result["valid"]:
            result["error_message"] = response.get("error_message", "Unknown error")

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

        result = {
            "valid": response.get("valid", False),
            "matched": response.get("test_result", {}).get("matched", False)
        }
        if not result["valid"]:
            result["error"] = response.get("error_message", "Unknown error")
        if response.get("test_result", {}).get("error"):
            result["test_error"] = response.get("test_result", {}).get("error", "Unknown error")

        return result
