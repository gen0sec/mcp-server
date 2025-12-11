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

    def validate_waf_expression(self, expression: str) -> str:
        """
        Validates a WAF expression through the WAF validation API.

        Args:
            expression (str): The WAF expression to validate.

        Returns:
            str: The result of the validation.
        """
        payload = {
            "expression": expression,
            "test_match": False
        }

        response = self._api_request(payload)

        result = {
            "valid": response.get("valid", False)
        }
        if not result["valid"]:
            result["error_message"] = response.get("error_message", "Unknown error")
        return result
    
    def test_waf_expression(self, expression: str, test_data: dict) -> dict:
        """
        Tests a WAF expression against provided test data through the WAF validation API.

        Args:
            expression (str): The WAF expression to test.
            test_data (dict): The test data to use for matching.

        Returns:
            dict: The result of the test including match information.
        """
        payload = {
            "expression": expression,
            "test_match": True,
            "mock_data": test_data
        }

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