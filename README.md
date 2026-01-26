# kiro2cc - Kiro Auth Token Manager

A Go CLI tool for managing Kiro authentication tokens and providing an Anthropic API proxy to AWS CodeWhisperer.

```
     Claude Code                Cherry Studio
          │                           │
          │                           │
          │                           │
          ▼                           │
    kiro2cc claude                    │
          │                           │
          ▼                           │
    kiro2cc export                    │
          │                           │
          ▼                           │
    kiro2cc server                    │
          │                           │
          ▼                           ▼
        claude                 kiro2cc server
```

## Features

- Read Kiro auth tokens from `~/.aws/sso/cache/kiro-auth-token.json`
- Refresh access tokens using the refresh token
- Export environment variables for use with other tools
- Start an HTTP proxy server that translates Anthropic API requests to AWS CodeWhisperer

## Installation

### From Releases

Download the pre-built binary for your platform from the [Releases](https://github.com/stevengonsalvez/ccproxykiro/releases) page.

### Build from Source

```bash
go build -o kiro2cc main.go
```

## Automated Builds

This project uses GitHub Actions for automated builds:

- When a new GitHub Release is created, binaries for Windows, Linux, and macOS are automatically built and uploaded to the Release page
- Tests run automatically on pushes to main branch and pull requests

## Usage

### 1. Read Token Information

```bash
./kiro2cc read
```

### 2. Refresh Token

```bash
./kiro2cc refresh
```

### 3. Export Environment Variables

```bash
# Linux/macOS
eval $(./kiro2cc export)

# Windows (CMD)
./kiro2cc export
# Then copy and paste the output commands

# Windows (PowerShell)
./kiro2cc export
# Then copy and paste the output commands
```

### 4. Configure Claude Code (Region Bypass)

```bash
./kiro2cc claude
```

### 5. Start Anthropic API Proxy Server

```bash
# Use default port 8080
./kiro2cc server

# Use custom port
./kiro2cc server 9000
```

## Proxy Server Usage

After starting the server, you can use it as follows:

1. Send Anthropic API requests to the local proxy server
2. The proxy translates requests to CodeWhisperer format and handles authentication
3. Responses are converted back to Anthropic API format

Example:

```bash
curl -X POST http://localhost:8080/v1/messages \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

### Supported Models

| Anthropic Model Name | CodeWhisperer Model |
|---------------------|---------------------|
| `claude-sonnet-4-20250514` | `CLAUDE_SONNET_4_20250514_V1_0` |
| `claude-3-5-haiku-20241022` | `CLAUDE_3_7_SONNET_20250219_V1_0` |

## Token File Format

The tool expects the token file at `~/.aws/sso/cache/kiro-auth-token.json` with this format:

```json
{
    "accessToken": "your-access-token",
    "refreshToken": "your-refresh-token",
    "expiresAt": "2024-01-01T00:00:00Z"
}
```

## Environment Variables

The `export` command outputs the following environment variables:

- `ANTHROPIC_BASE_URL`: `http://localhost:8080`
- `ANTHROPIC_API_KEY`: The current access token

## Cross-Platform Support

- **Windows**: Uses `set` command format (CMD) and `$env:` format (PowerShell)
- **Linux/macOS**: Uses `export` command format
- Automatic detection of user home directory path
