[![MseeP Badge](https://mseep.net/pr/alxspiker-windows-command-line-mcp-server-badge.jpg)](https://mseep.ai/app/alxspiker-windows-command-line-mcp-server)

# Windows Command Line MCP Server

A secure Model Context Protocol (MCP) server that enables AI models to interact with Windows command-line functionality safely and efficiently.

![Version](https://img.shields.io/badge/version-0.3.0-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
[![smithery badge](https://smithery.ai/badge/@alxspiker/Windows-Command-Line-MCP-Server)](https://smithery.ai/server/@alxspiker/Windows-Command-Line-MCP-Server)

## Overview

The Windows Command Line MCP Server provides a robust, secure bridge between AI models and Windows system operations. It allows controlled execution of commands, project creation, and system information retrieval while maintaining strict security protocols.

## Key Features

### 🔒 Enhanced Security
- Comprehensive command allowlist
- Strict input validation
- Prevention of destructive system operations
- Configurable security levels

### 🛠 Development Tools Support
- Project creation for React, Node.js, and Python
- Safe development environment interactions
- Expanded command support for development workflows

### 🖥 System Interaction Capabilities
- Execute Windows CLI commands
- Run PowerShell scripts
- Retrieve system and network information
- Manage processes and services

## Installation

### Installing via Smithery

To install Windows Command Line MCP Server for Claude Desktop automatically via [Smithery](https://smithery.ai/server/@alxspiker/Windows-Command-Line-MCP-Server):

```bash
npx -y @smithery/cli install @alxspiker/Windows-Command-Line-MCP-Server --client claude
```

### Prerequisites
- Node.js 16 or later
- npm or yarn
- Windows operating system

### Setup
```bash
git clone https://github.com/alxspiker/Windows-Command-Line-MCP-Server.git
cd Windows-Command-Line-MCP-Server
npm install
npm run build
```

## Usage

### Command Line Options
- Default mode: Uses predefined safe commands
- `--allow-all`: Run in extended mode (with additional precautions)
- Custom command lists can be specified as arguments

### Project Creation
Create new projects safely with the built-in project creation tool:
- Supported project types: React, Node.js, Python
- Projects created in a sandboxed `~/AIProjects` directory

### Available Tools
1. **execute_command**: Run Windows CLI commands (supports a persistent working directory and optional background execution)
2. **execute_powershell**: Execute PowerShell scripts (supports a persistent working directory and optional background execution)
3. **get_background_output**: Fetch stdout/stderr and status for a command started with `runInBackground`
4. **list_background_processes**: List all background processes and their status
5. **stop_background_process**: Terminate a running background process
6. **list_running_processes**: Retrieve active system processes
7. **get_system_info**: Collect system configuration details
8. **get_network_info**: Retrieve network adapter information
9. **get_scheduled_tasks**: List and query system tasks
10. **get_service_info**: Manage and query Windows services
11. **list_allowed_commands**: List all commands that can be executed by the server

## Using with Claude for Desktop

To use this server with Claude for Desktop:

1. Build the server using the setup instructions above
2. Add it to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "windows-cmd": {
      "command": "node",
      "args": ["/path/to/dist/index.js"]
    }
  }
}
```

Replace `/path/to/dist/index.js` with the absolute path to the built `index.js` file in the `dist` directory.

3. Restart Claude for Desktop
4. You can now use the tools by asking Claude to perform Windows system operations

## Running as an HTTP MCP Server

By default the server communicates over stdio, for clients (like Claude Desktop) that spawn it as a local subprocess. It can also run as a standalone HTTP service exposing the standard MCP Streamable HTTP transport at `/mcp` (`POST`/`GET`/`DELETE`), the same way you'd reach any remote MCP server.

```bash
# Windows (cmd/PowerShell)
set MCP_TRANSPORT=http
node dist/index.js

# or, cross-platform via the npm script
npm run start:http
```

Environment variables:

| Variable | Default | Description |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` | Set to `http` to run the Streamable HTTP server instead of stdio. |
| `MCP_HOST` | `127.0.0.1` | Interface to bind. Binding beyond localhost is only safe with `MCP_AUTH_TOKEN` set. |
| `MCP_PORT` | `3000` | Port to listen on. |
| `MCP_AUTH_TOKEN` | *(none)* | Shared secret. If set, all `/mcp` requests must present it, either as `Authorization: Bearer <token>` directly, or via the OAuth flow below. |
| `MCP_PUBLIC_URL` | derived from `MCP_HOST`/`MCP_PORT` | The externally-reachable base URL for this server (e.g. `https://mcp.example.com`), used for OAuth issuer/redirect URLs. Required if the server sits behind a reverse proxy or tunnel. |

Point any MCP-over-HTTP client at `http://<host>:<port>/mcp`.

Variables can also be placed in a `.env.local` file in the directory the server is run from - it's loaded automatically on startup (and never overrides variables already set in the environment). Copy [`.env.local.example`](.env.local.example) to `.env.local` and fill in what you need to get started.

> **⚠️ This server executes commands on the host machine.** Anyone who can reach the `/mcp` endpoint can run Windows commands with the privileges of the process. Never bind to `0.0.0.0` or a public interface without `MCP_AUTH_TOKEN` set, and prefer putting it behind a reverse proxy / VPN / firewall rule that restricts access even when a token is configured.

### Connecting OAuth-only clients (e.g. Claude.ai custom connectors)

Some remote MCP clients always perform an OAuth handshake before connecting, rather than letting you supply a bearer token directly. When `MCP_AUTH_TOKEN` is set, this server exposes a minimal OAuth 2.1 authorization server alongside the resource server, so those clients work without any extra configuration:

- Discovery metadata at `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource/mcp`
- Open dynamic client registration at `/register` (any client may register - the shared secret is what actually gates access, not the client id)
- `/authorize` shows a one-field login page asking for the `MCP_AUTH_TOKEN` value; entering it correctly issues an authorization code
- `/token` exchanges that code (via standard PKCE) for a bearer token accepted by `/mcp`

To use it, add this server as a custom connector using `http://<host>:<port>/mcp` (or your `MCP_PUBLIC_URL` + `/mcp`) as the URL - the client will discover the endpoints above automatically and prompt you for the token in a browser tab. If `MCP_AUTH_TOKEN` is not set, `/authorize` auto-approves with no prompt, which is only appropriate for a server bound to localhost.

Note that OAuth issuer URLs must be `https://` unless the host is `localhost`/`127.0.0.1` - set `MCP_PUBLIC_URL` to your public HTTPS URL when running behind a reverse proxy or tunnel, or the server will log a warning and fall back to plain bearer-token auth only.

## Security Considerations

### Allowed Commands
By default, only safe commands are permitted:
- System information retrieval
- Network configuration
- Process management
- Development tool interactions

### Blocked Operations
Dangerous commands are always blocked, including:
- Disk formatting
- User management
- System shutdown
- Critical registry modifications

## Configuration

Customize the server's behavior by specifying allowed commands or using configuration flags.

### Example
```bash
# Run with default safe commands
node dist/index.js

# Run with specific allowed commands
node dist/index.js dir echo npm git

# Run in extended mode (use with caution)
node dist/index.js --allow-all
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- Inspired by the Model Context Protocol specification
- Developed with security and flexibility in mind

## Version History

- **0.3.0**: Implemented all tools mentioned in README (system info, network info, process management, service info)
- **0.2.0**: Added project creation, expanded development tools
- **0.1.0**: Initial release with basic command execution capabilities

## Support

For issues, questions, or suggestions, please [open an issue](https://github.com/alxspiker/Windows-Command-Line-MCP-Server/issues) on GitHub.
