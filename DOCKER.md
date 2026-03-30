# Docker Setup

This document explains how to build and run the Perplexity MCP Server using Docker.

## Prerequisites

- Docker installed on your system
- A Perplexity API key from the [API Portal](https://www.perplexity.ai/account/api/group)

## Building the Docker Image

Build the Docker image from the project root:

```bash
docker build -t perplexity-mcp-server .
```

## Docker Compose (Recommended)

This repository includes a ready-to-run Compose setup:

- `docker-compose.yml`
- `.env.compose.example`

### 1. Prepare environment file

```bash
cp .env.compose.example .env.compose
```

Edit `.env.compose` for your deployment.

For your case (MCP client on `numira.ai`, server on `192.168.0.34:8080`), make sure:

- `ALLOWED_ORIGINS=https://numira.ai`
- `OAUTH_PUBLIC_BASE_URL` points to the URL your MCP client can reach
- `OAUTH_ISSUER_URL` and `OAUTH_RESOURCE_SERVER_URL` match that same reachable URL

> If you use `http://` for issuer URLs (LAN/dev), keep `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL=1`.
> For production, use HTTPS and remove this flag.

### 2. Start services

```bash
docker compose up -d --build
```

### 3. Check health

```bash
curl -i http://127.0.0.1:8080/health
```

### 4. Stop services

```bash
docker compose down
```

## Running the Container

### HTTP Mode (Default)

The Docker container runs in HTTP mode by default, making it accessible via HTTP requests:

```bash
docker run --rm -p 8080:8080 -e PERPLEXITY_API_KEY=your_key_here perplexity-mcp-server
```

The server will be accessible at `http://localhost:8080/mcp`

### With Custom Timeout

Set a custom timeout for requests (default is 5 minutes):

```bash
docker run --rm -p 8080:8080 \
  -e PERPLEXITY_API_KEY=your_key_here \
  -e PERPLEXITY_TIMEOUT_MS=600000 \
  perplexity-mcp-server
```

### With Proxy Support

If you're behind a corporate proxy, configure it:

```bash
docker run --rm -p 8080:8080 \
  -e PERPLEXITY_API_KEY=your_key_here \
  -e PERPLEXITY_PROXY=https://your-proxy-host:8080 \
  perplexity-mcp-server
```

Or with authentication:

```bash
docker run --rm -p 8080:8080 \
  -e PERPLEXITY_API_KEY=your_key_here \
  -e PERPLEXITY_PROXY=https://username:password@your-proxy-host:8080 \
  perplexity-mcp-server
```

### Using Environment File

Create a `.env` file:

```bash
PERPLEXITY_API_KEY=your_key_here
PERPLEXITY_TIMEOUT_MS=600000
PERPLEXITY_PROXY=https://your-proxy-host:8080
PORT=8080
```

Then run:

```bash
docker run --rm -p 8080:8080 --env-file .env perplexity-mcp-server
```

## Integration with MCP Clients

When using the HTTP Docker server, configure your MCP client to connect to the HTTP endpoint:

```json
{
  "mcpServers": {
    "perplexity": {
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

## STDIO Mode (Local Development)

For local development with STDIO transport, you can still run the server locally without Docker:

```bash
npm install
npm run build
PERPLEXITY_API_KEY=your_key_here npm start
```

> **Note**: The Docker image is optimized for HTTP mode deployment. For local STDIO usage, the `npx` method documented in the main README is recommended.
