from mcp.server.fastmcp import FastMCP
import logging
from pathlib import Path
import argparse
import uvicorn
import signal
import sys

from waf_rule_mpc.config import Config
from waf_rule_mpc.cve_source_manager import CVESourceManager
from waf_rule_mpc.waf_context_manager import WirefilterWAFContextManager
from waf_rule_mpc.prompt_manager import PromptManager
from waf_rule_mpc.tools import WAFValidator
from waf_rule_mpc.resource_updater import ResourceUpdater

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize configuration
config_path = Path(__file__).parent / "config.yaml"
config = Config().from_yaml(config_path)
logger.info(f"WAF Validation API URL: {config.WAF_VALIDATION_API_URL}")

# Initialize resource managers
cve_source_manager = CVESourceManager(
    config.EXPLOIT_REPOSITORIES,
    config.REPO_FOLDER,
    config.NUCLEI_TEMPLATES_VERSION,
    config.NUCLEI_TEMPLATES_AUTO_UPDATE
)
waf_context_manager = WirefilterWAFContextManager(config.WAF_CONTEXT_URLS, config.CONTEXT_FOLDER)
prompt_manager = PromptManager(config.PROMPTS_FOLDER)

# Initialize and start resource updator
resource_updater = ResourceUpdater(waf_context_manager, cve_source_manager, config.RESOURCE_UPDATE_INTERVAL)

# Always download nuclei templates at startup (if version is configured or auto-update is enabled)
# This ensures templates are available even if resource updater isn't running
if config.NUCLEI_TEMPLATES_VERSION or config.NUCLEI_TEMPLATES_AUTO_UPDATE:
    if config.NUCLEI_TEMPLATES_AUTO_UPDATE:
        logger.info("Auto-update enabled: downloading latest nuclei-templates at startup...")
    else:
        logger.info(f"Downloading nuclei-templates version {config.NUCLEI_TEMPLATES_VERSION} at startup...")
    try:
        cve_source_manager.clone_cve_repositories()
    except Exception as e:
        logger.error(f"Failed to download nuclei-templates at startup: {e}")

# Start resource updater for periodic updates
# Note: Context files are now local, but we still need periodic updates for nuclei templates
resource_updater.start()
logger.info("Resource updater started for periodic nuclei-templates updates.")

# Setup signal handlers for clean shutdown
def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info(f"Received signal {signum}, shutting down...")
    resource_updater.stop()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Initialize the WAF validator service
waf_validator = WAFValidator(validation_url=config.WAF_VALIDATION_API_URL)

# Initialize the MCP server
mcp = FastMCP("WAF rule generation", json_response=True)

# Add resoruces to the MCP server
@mcp.resource("wafcontext://actions")
def waf_actions():
    """Reference on actions available in the Rules language."""
    return waf_context_manager.read_context_file("actions")

@mcp.resource("wafcontext://expressions")
def waf_expressions():
    """Reference on expressions available in the Rules language."""
    return waf_context_manager.read_context_file("expressions")

@mcp.resource("wafcontext://fields")
def waf_fields():
    """Reference on fields available in the Rules language."""
    return waf_context_manager.read_context_file("fields")

@mcp.resource("wafcontext://functions")
def waf_functions():
    """Reference on functions available in the Rules language."""
    return waf_context_manager.read_context_file("functions")

@mcp.resource("wafcontext://operators")
def waf_operators():
    """Reference on operators available in the Rules language."""
    return waf_context_manager.read_context_file("operators")

@mcp.resource("wafcontext://values")
def waf_values():
    """Refernece on values available in the Rules language."""
    return waf_context_manager.read_context_file("values")

# Add tools to the MCP server
@mcp.tool(
    name="fetch_cve_vulnerability_template",
    title="Fetch CVE vulnerability template",
    description="Retrieve a CVE Indexed vulnerability template, providing additional information for the exploit. The returned file is a CVE Vulnerability Template that packages all relevant information about a specific CVE, including its metadata, severity, description, references, classification, and characteristic request patterns. It also includes protocol flows, payload structures, and contextual artifacts that help security systems or LLMs derive precise defensive controls—such as intrusion signatures, anomaly indicators, or WAF rule recommendations."
)
def fetch_cve_vulnerability_template(cve_id: str) -> dict:
    """
    Retrieve a CVE Indexed vulnerability template, providing additional information for the exploit.

    The returned file is a CVE Vulnerability Template that packages all relevant information about a specific CVE,
    including its metadata, severity, description, references, classification, and characteristic request patterns.
    It also includes protocol flows, payload structures, and contextual artifacts
    that help security systems or LLMs derive precise defensive controls—such as
    intrusion signatures, anomaly indicators, or WAF rule recommendations.
    """
    result = cve_source_manager.fetch_cve_file(cve_id)
    return result

@mcp.tool(
    name="validate_waf_expression",
    title="Validate WAF expression",
    description="Validate a Wirefilter WAF (Web Application Firewall) expression. Optionally test against custom test data. Returns a dictionary with valid (boolean) indicating if the expression is syntactically valid, and error_message (string) containing a human-readable validation error message if invalid."
)
def validate_waf_expression(expression: str, test: dict = None) -> dict:
    """
    Validate a Wirefilter WAF (Web Application Firewall) expression.

    Input:
    expression (string) — A Wirefilter WAF expression to validate.
    test (object, optional) — Optional custom test data to use for matching. If provided, the expression will also be tested against this data.

    Expected Input Example (without test):
    {
        "expression": "(ip.src in {10.0.0.1 10.0.0.2}) and (http.request.uri.path contains \"/admin\")"
    }

    Expected Input Example (with test):
    {
        "expression": "(ip.src in {10.0.0.1 10.0.0.2}) and (http.request.uri.path contains \"/admin\")",
        "test": {
            "http.request.method": "GET",
            "http.request.path": "/admin/dashboard",
            "ip.src": "10.0.0.1"
        }
    }

    Output:
    A dictionary with the following fields:
        valid (boolean) — true if the expression is syntactically valid; false otherwise.
        error_message (string) — A human-readable validation error message. Empty when valid is true.
        matched (boolean, optional) — Present if test data was provided. Indicates if the expression matched the test data.
        test_error (string, optional) — Present if test data was provided and test failed. Contains error message.

    Example Output (valid expression without test):
    {
        "valid": true
    }
    Example Output (valid expression with test):
    {
        "valid": true,
        "matched": true
    }
    Example Output (invalid expression):
    {
        "valid": false,
        "error_message": "Unexpected token 'andd' at position 23."
    }
    """
    result = waf_validator.validate_waf_expression(expression, test)
    return result

@mcp.tool(
    name="validate_waf_expression_with_tests",
    title="Validate WAF expression with tests",
    description="Validate a Wirefilter WAF rule expression, optionally against a full HTTP request example. Returns a dictionary with valid (boolean), error_message (string), matched (boolean) indicating if the test request matches the rule, and test_error (string) if the test fails."
)
def validate_waf_expression_with_tests(rule: str, test: dict = None) -> dict:
    """
    Validate a Wirefilter WAF rule expression, optionally against a full HTTP request example.

    Input:
    rule (string) — The WAF rule expression to validate.
    test (object, optional) — An optional custom test data object used for testing the rule. If not provided, uses default mock data. Includes the following fields:
        http.request.method (string)
        http.request.scheme (string)
        http.request.host (string)
        http.request.port (number)
        http.request.path (string)
        http.request.uri (string)
        http.request.query (string)
        http.request.user_agent (string)
        http.request.content_type (string)
        http.request.content_length (number)
        http.request.body (string)
        http.request.body_sha256 (string)
        http.request.headers (object) — Additional key-value string pairs
        ip.src (string)
        ip.src.country (string)
        ip.src.asn (number)
        ip.src.asn_org (string)
        ip.src.asn_country (string)
        threat.score (number)
        threat.advice (string)

    When a body is given, its hash and length are calculated by default. If hash and length are provided, those values override the calculated ones.

    Example Input:
    {
    "rule": "(ip.src in {\"10.0.0.1\", \"10.0.0.2\"}) and (http.request.uri.path contains \"/admin\")",
    "test": {
        "http.request.method": "GET",
        "http.request.scheme": "https",
        "http.request.host": "example.com",
        "http.request.port": 443,
        "http.request.path": "/admin/dashboard",
        "http.request.uri": "/admin/dashboard?user=123",
        "http.request.query": "user=123",
        "http.request.user_agent": "Mozilla/5.0",
        "http.request.content_type": "application/json",
        "http.request.content_length": 0,
        "http.request.body": "",
        "http.request.body_sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
        "http.request.headers": {
            "X-Forwarded-For": "10.0.0.1"
        },
        "ip.src": "10.0.0.1",
        "ip.src.country": "US",
        "ip.src.asn": 15169,
        "ip.src.asn_org": "Google LLC",
        "ip.src.asn_country": "US",
        "threat.score": 0,
        "threat.advice": ""
        }
    }

    Output:
    A dictionary with the following fields:
        valid (boolean) — true if the expression is syntactically valid; false otherwise.
        error_message (string) — A human-readable validation error message.
        matched (boolean) - true if the given test request matches with the rules
        test_error (string) - A human-readable error message if the test fails.

    Example Output (valid expression):
    {
        "valid": true,
        "matched": true
    }
    Example Output (invalid test):
    {
        "valid": false,
        "matched": false,
        "error": "Unknown error",
        "test_error": "Failed to create filter: error building scheme for field 'http.request.port': unsupported type: float64"
    }
    """
    result = waf_validator.test_waf_expression(rule, test)
    return result

@mcp.tool(
    name="get_waf_context",
    title="Get WAF context",
    description="Fetch WAF context from Wirefilter documentation about actions, expressions, fields, functions, operators and values."
)
def get_waf_context():
    """
    Fetch WAF context from Wirefilter documentation about actions, expressions, fields, functions, operators and values.
    """
    result = {}
    for context in ["actions", "expressions", "fields", "functions", "operators", "values"]:
        result[context] = waf_context_manager.read_context_file(context)

    return result

# Add prompts to the MCP server
@mcp.prompt(
    name="natural_waf_rule_generation_prompt",
    title="Rule generation from natural language",
    description="Outlines steps for generating a WAF rule from a natural language description"
)
def natural_waf_rule_generation_prompt() -> str:
    """Returns a prompt that outlines the steps for generating a WAF rule"""
    prompt = prompt_manager.read_prompt_file("gen_from_desc")
    return prompt

@mcp.prompt(
    name="cve_waf_rule_generation_prompt",
    title="Waf rule generation based on CVE index",
    description="Outlines steps for generating a WAF rule from a CVE index"
)
def cve_waf_rule_generation_prompt() -> str:
    prompt = prompt_manager.read_prompt_file("gen_from_cve")
    return prompt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run MCP server with specified transport.")
    parser.add_argument(
        "--transport",
        type=str,
        choices=["stdio", "streamable-http", "sse"],
        default="stdio",
        help="Transport mode for MCP server"
    )
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Host to bind to (default: 0.0.0.0 for HTTP transports, not used for stdio)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to bind to (default: 8000 for HTTP transports, not used for stdio)"
    )
    parser.add_argument(
        "--workspace",
        type=str,
        default=None,
        help="Workspace directory (optional, for compatibility)"
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["debug", "info", "warning", "error", "critical"],
        default="info",
        help="Set the logging level (default: info)"
    )
    # Use parse_known_args to ignore unknown args that MCP client might pass
    args, unknown = parser.parse_known_args()

    # Set logging level based on argument
    if unknown:
        logger.debug(f"Ignoring unknown arguments: {unknown}")
    log_level = getattr(logging, args.log_level.upper())
    logging.getLogger().setLevel(log_level)
    logger.setLevel(log_level)

    try:
        if args.transport == "stdio":
            logger.info("Starting MCP server with stdio transport...")
            mcp.run(transport=args.transport)
        else:
            # For HTTP transports, FastMCP uses uvicorn internally
            # Set environment variables that uvicorn respects
            host = args.host if args.host is not None else "0.0.0.0"
            port = args.port if args.port is not None else 8000

            import os
            os.environ["UVICORN_HOST"] = host
            os.environ["UVICORN_PORT"] = str(port)

            # Patch uvicorn.Config to intercept and modify host/port
            _original_uvicorn_config_init = uvicorn.Config.__init__

            def _patched_uvicorn_config_init(self, *args, **kwargs):
                """Patch uvicorn.Config to force our host/port"""
                # Force override host and port
                kwargs["host"] = host
                kwargs["port"] = port
                return _original_uvicorn_config_init(self, *args, **kwargs)

            # Also patch uvicorn.run
            _original_uvicorn_run = uvicorn.run

            def _patched_uvicorn_run(app, **kwargs):
                """Patch uvicorn.run to force our host/port"""
                kwargs["host"] = host
                kwargs["port"] = port
                return _original_uvicorn_run(app, **kwargs)

            # Also patch uvicorn.Server to modify config after creation
            _original_uvicorn_server_init = uvicorn.Server.__init__

            def _patched_uvicorn_server_init(self, config, **kwargs):
                """Patch uvicorn.Server to force host/port in config"""
                # Modify config object directly
                if hasattr(config, 'host'):
                    config.host = host
                if hasattr(config, 'port'):
                    config.port = port
                return _original_uvicorn_server_init(self, config, **kwargs)

            # Apply patches
            uvicorn.Config.__init__ = _patched_uvicorn_config_init
            uvicorn.run = _patched_uvicorn_run
            uvicorn.Server.__init__ = _patched_uvicorn_server_init

            try:
                logger.info("Starting MCP server with HTTP transport...")
                mcp.run(transport=args.transport)
            except KeyboardInterrupt:
                logger.info("Received interrupt signal, shutting down...")
                raise
            finally:
                # Restore original
                uvicorn.Config.__init__ = _original_uvicorn_config_init
                uvicorn.run = _original_uvicorn_run
                uvicorn.Server.__init__ = _original_uvicorn_server_init
                # Clean up environment variables
                os.environ.pop("UVICORN_HOST", None)
                os.environ.pop("UVICORN_PORT", None)
    except KeyboardInterrupt:
        logger.info("Shutting down MCP server...")
        resource_updater.stop()
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error running MCP server: {e}")
        resource_updater.stop()
        sys.exit(1)
