from mcp.server.fastmcp import FastMCP
import logging
from pathlib import Path
import argparse
import uvicorn
import signal
import sys
from http import HTTPStatus
from starlette.responses import Response

from waf_rule_mpc.config import Config
from waf_rule_mpc.plugins import CVEPluginManager, NucleiOpenSourcePlugin, ProjectDiscoveryPlugin
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

# Initialize plugin manager
plugin_manager = CVEPluginManager()

# Register Nuclei Open Source plugin
if config.NUCLEI_OPENSOURCE_ENABLED:
    nuclei_oss_plugin = NucleiOpenSourcePlugin(
        repo_folder=str(config.REPO_FOLDER),
        version=config.NUCLEI_TEMPLATES_VERSION,
        auto_update=config.NUCLEI_TEMPLATES_AUTO_UPDATE,
        priority=config.NUCLEI_OPENSOURCE_PRIORITY,
        enabled=True
    )
    plugin_manager.register(nuclei_oss_plugin)
    logger.info(f"Nuclei Open Source plugin registered (priority={config.NUCLEI_OPENSOURCE_PRIORITY})")

# Register ProjectDiscovery plugin
if config.PROJECTDISCOVERY_ENABLED and config.PROJECTDISCOVERY_API_KEY:
    projectdiscovery_plugin = ProjectDiscoveryPlugin(
        api_key=config.PROJECTDISCOVERY_API_KEY,
        priority=config.PROJECTDISCOVERY_PRIORITY,
        enabled=True
    )
    plugin_manager.register(projectdiscovery_plugin)
    logger.info(f"ProjectDiscovery plugin registered (priority={config.PROJECTDISCOVERY_PRIORITY})")
elif config.PROJECTDISCOVERY_ENABLED:
    logger.warning("ProjectDiscovery plugin enabled but no API key provided")

# Initialize other managers
waf_context_manager = WirefilterWAFContextManager(config.WAF_CONTEXT_URLS, config.CONTEXT_FOLDER)
prompt_manager = PromptManager(config.PROMPTS_FOLDER)

# Initialize plugins at startup
logger.info("Initializing CVE source plugins...")
init_results = plugin_manager.initialize_all()
for plugin_name, success in init_results.items():
    if success:
        logger.info(f"Initialized: {plugin_name}")
    else:
        logger.warning(f"Failed to initialize: {plugin_name}")

# Initialize and start resource updater
resource_updater = ResourceUpdater(waf_context_manager, plugin_manager, config.RESOURCE_UPDATE_INTERVAL)
resource_updater.start()
logger.info("Resource updater started for periodic plugin updates.")

# Setup signal handlers for clean shutdown
def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info(f"Received signal {signum}, shutting down...")
    resource_updater.stop()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Workaround for MCP Python SDK bug: return 404 instead of 400 when session ID is missing/invalid
def patch_streamable_http_session_manager():
    try:
        from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    except Exception as e:
        logger.warning(f"StreamableHTTPSessionManager patch skipped (import failed): {e}")
        return

    original_handle = StreamableHTTPSessionManager._handle_stateful_request

    # https://github.com/modelcontextprotocol/python-sdk/issues/1727
    async def _patched_handle_stateful_request(self, scope, receive, send):
        """Patched version that converts 400 to 404 for invalid session IDs."""
        pending_start = None  # Buffer for start message if we see a 400

        async def patched_send(message):
            nonlocal pending_start

            msg_type = message.get("type")

            if msg_type == "http.response.start":
                status = message.get("status", 200)
                # If it's a 400, buffer it and wait for body to confirm
                if status == HTTPStatus.BAD_REQUEST:
                    pending_start = message
                    return  # Don't send yet
                else:
                    # For non-400, send immediately
                    await send(message)
                    return

            elif msg_type == "http.response.body":
                # If we have a pending 400 start message, check the body
                if pending_start is not None:
                    body = message.get("body", b"")
                    body_str = body.decode("utf-8", errors="ignore") if isinstance(body, bytes) else str(body)

                    # If it's the session ID error, change to 404
                    if "No valid session ID provided" in body_str:
                        # Send 404 start message instead
                        await send({
                            "type": "http.response.start",
                            "status": HTTPStatus.NOT_FOUND,
                            "headers": pending_start.get("headers", []),
                        })
                    else:
                        # Not the session ID error, send original 400
                        await send(pending_start)

                    pending_start = None
                    # Send body as-is
                    await send(message)
                    return
                else:
                    # No pending start, forward normally
                    await send(message)
                    return

            # For any other message type, forward as-is
            await send(message)

        # Call original with patched send
        await original_handle(self, scope, receive, patched_send)

    StreamableHTTPSessionManager._handle_stateful_request = _patched_handle_stateful_request
    logger.info("Applied 400->404 workaround for missing/invalid MCP session ID.")

# Apply the workaround before server start
patch_streamable_http_session_manager()

# Initialize the WAF validator service
waf_validator = WAFValidator(validation_url=config.WAF_VALIDATION_API_URL)

# Initialize the MCP server
mcp = FastMCP("WAF rule generation", json_response=True)

# Add resources to the MCP server
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
    description="Retrieve a CVE Indexed vulnerability template from multiple sources (Nuclei Open Source, Nuclei Paid API). Returns detailed information for the exploit including metadata, severity, description, references, classification, and characteristic request patterns."
)
def fetch_cve_vulnerability_template(cve_id: str, source: str = None) -> dict:
    """
    Retrieve a CVE Indexed vulnerability template from configured sources.

    The server queries CVE sources in priority order. The first source to return data wins.

    Args:
        cve_id: The CVE identifier (e.g., "CVE-2025-55182")
        source: Optional specific source to query (e.g., "Nuclei Paid (ProjectDiscovery API)")

    Returns:
        Dictionary containing CVE data including:
        - success: Whether CVE was found
        - cve_id: The CVE identifier
        - source: Which plugin returned the data
        - content: The vulnerability template content
        - metadata: Additional information from the source
    """
    result = plugin_manager.fetch_cve(cve_id, source)
    return result


@mcp.tool(
    name="list_cve_sources",
    title="List CVE sources",
    description="List all registered CVE source plugins and their status."
)
def list_cve_sources() -> dict:
    """
    List all registered CVE source plugins.

    Returns:
        Dictionary containing list of plugins with their status
    """
    return {
        "sources": plugin_manager.list_plugins()
    }


@mcp.tool(
    name="fetch_cve_from_all_sources",
    title="Fetch CVE from all sources",
    description="Fetch CVE vulnerability template from ALL enabled sources. Useful for comparing data across different sources."
)
def fetch_cve_from_all_sources(cve_id: str) -> dict:
    """
    Fetch CVE data from all enabled sources.

    Args:
        cve_id: The CVE identifier (e.g., "CVE-2025-55182")

    Returns:
        Dictionary containing results from all sources
    """
    return plugin_manager.fetch_cve_from_all(cve_id)


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
