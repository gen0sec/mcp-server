# Gen0Sec WAF Rule Generation MCP Server

This service provides a WAF rule generation MCP Server. The server provides testing tools for Wirefilter WAF rules and additional context for helping th LLM generate correct rules.

## Features

#### Server features

- Downloads and periodically updates Wirefilter WAF information and CVE explot template repository
- Uses external WAF validation API for validating and testing WAF expressions
- Provides configuration from YAML file
- Provides tools and resources through MCP for agentic LLMs

#### MCP features

- Tools:
  - `fetch_cve_vulnerability_template` - Fetch an exploit template for a specific CVE identifier
  - `validate_waf_expression` - Validate a WAF expression
  - `validate_waf_expression_with_tests` - Validate a WAF expression and test it against mock data
  - `get_waf_context` - Fetch all Wirefilter WAF context information
- Resources
  - `wafcontext://actions` - Reference on actions available in the Rules language.
  - `wafcontext://expressions` - Reference on expressions available in the Rules language.
  - `wafcontext://fields` - Reference on fields available in the Rules language.
  - `wafcontext://fundtions` - Reference on fundtions available in the Rules language.
  - `wafcontext://operators` - Reference on operators available in the Rules language.
  - `wafcontext://values` - Reference on values available in the Rules language.
- Prompts:
  - `natural_waf_rule_generation_prompt` - Provides prompt for helping rule generation from natural language description
  - `cve_waf_rule_generation_prompt` - Provides prompt for helping rule generation from a CVE identifier

## Setup

### Local setup for Claude Desktop

#### Prerequisites

- `uv`
  - Needed for running the server through Claude Desktop.
  - Installation: `curl -LsSf https://astral.sh/uv/install.sh | sh`
  - Installation (with brew): `brew install uv`
- `mcpb`
  - Needed for easy Claude Desktop integration.
  - Installation: `npm install -g @anthropic-ai/mcpb`
- `git`
  - Needed to pull repository for CVE templates.
  - Installation (with brew): `brew install git`

#### Other services

The WAF rule validation API needs to be running for WAF rule validation to work.
The URL for this can be given in the Claude Desktop configuration.

#### Setup

1. Run the `mcpb pack` command in the root folder. This will create a `gen0sec-mcp-server.mcpb` file.
2. Opening the generated file will allow the installation of it on Caldue Desktop.
3. Setting up takes a minute but after that the tools and resources are available to use in Claude Desktop.

### Cursor IDE Integration

#### Prerequisites

- `uv` (for local stdio setup)
  - Installation: `curl -LsSf https://astral.sh/uv/install.sh | sh`
  - Installation (with brew): `brew install uv`
- `git` (needed to pull repository for CVE templates)
  - Installation (with brew): `brew install git`

#### Option 1: Local Setup (stdio)

1. Create or edit the MCP configuration file:
   - **macOS/Linux:** `~/.cursor/mcp.json`
   - **Windows:** `%USERPROFILE%\.cursor\mcp.json`

2. Add the following configuration:

```json
{
  "mcpServers": {
    "waf-rule-mcp": {
      "command": "uv",
      "args": [
        "run",
        "--project",
        "/absolute/path/to/mcp-server",
        "/absolute/path/to/mcp-server/server/main.py"
      ],
      "env": {
        "WAF_VALIDATION_API_URL": "https://public.gen0sec.com/v1/waf/validate"
      }
    }
  }
}
```

**Notes:**
- Replace `/absolute/path/to/mcp-server` with the absolute path to your project directory
- The `WAF_VALIDATION_API_URL` environment variable is optional - if not set, it will use the value from `server/config.yaml`

3. Restart Cursor IDE to apply the changes.

#### Option 2: Docker Setup (HTTP)

1. Build and run the Docker container:
   ```bash
   docker build -t waf-rule-mcp .
   docker run -p 8000:8000 waf-rule-mcp
   ```

2. Create or edit the MCP configuration file:
   - **macOS/Linux:** `~/.cursor/mcp.json`
   - **Windows:** `%USERPROFILE%\.cursor\mcp.json`

3. Add the following configuration:

```json
{
  "mcpServers": {
    "waf-rule-mcp": {
      "url": "http://localhost:8000"
    }
  }
}
```

4. Restart Cursor IDE to apply the changes.

### Dockerfile

1. Build the Docker Image from the project root: `docker build -t waf-rule-mcp .`
2. Run the Container `docker run -p 8000:8000 waf-rule-mcp`
