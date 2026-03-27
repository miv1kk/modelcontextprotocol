#!/usr/bin/env node

import { randomBytes, randomUUID } from "node:crypto";
import express from "express";
import cors from "cors";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { InvalidGrantError, InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { createPerplexityServer } from "./server.js";
import { logger } from "./logger.js";

const OAUTH_SCOPE = "perplexity.api";

interface PendingAuthorization {
  clientId: string;
  params: AuthorizationParams;
  createdAt: number;
}

interface AuthorizationCodeRecord {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource?: URL;
  perplexityApiKey: string;
}

interface RefreshTokenRecord {
  clientId: string;
  scopes: string[];
  resource?: URL;
  perplexityApiKey: string;
}

function createToken(length: number = 32): string {
  return randomBytes(length).toString("hex");
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

class InMemoryClientsStore implements OAuthRegisteredClientsStore {
  private readonly clients = new Map<string, OAuthClientInformationFull>();

  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    return this.clients.get(clientId);
  }

  async registerClient(client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">): Promise<OAuthClientInformationFull> {
    const now = Math.floor(Date.now() / 1000);
    const clientId = `client_${createToken(12)}`;
    const tokenEndpointAuthMethod = client.token_endpoint_auth_method || "none";
    const requiresClientSecret = tokenEndpointAuthMethod !== "none";

    const registeredClient: OAuthClientInformationFull = {
      ...client,
      client_id: clientId,
      client_id_issued_at: now,
      token_endpoint_auth_method: tokenEndpointAuthMethod,
      ...(requiresClientSecret
        ? {
            client_secret: createToken(24),
            client_secret_expires_at: 0,
          }
        : {}),
    };

    this.clients.set(clientId, registeredClient);
    return registeredClient;
  }
}

class PerplexityOAuthProvider implements OAuthServerProvider {
  public readonly clientsStore: OAuthRegisteredClientsStore = new InMemoryClientsStore();

  private readonly pendingAuthorizations = new Map<string, PendingAuthorization>();
  private readonly authorizationCodes = new Map<string, AuthorizationCodeRecord>();
  private readonly refreshTokens = new Map<string, RefreshTokenRecord>();
  private readonly accessTokens = new Map<string, AuthInfo>();

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: express.Response): Promise<void> {
    const requestId = randomUUID();
    this.pendingAuthorizations.set(requestId, {
      clientId: client.client_id,
      params,
      createdAt: Date.now(),
    });
    res.redirect(302, `/oauth/consent?request_id=${encodeURIComponent(requestId)}`);
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    const record = this.authorizationCodes.get(authorizationCode);
    if (!record || record.clientId !== client.client_id) {
      throw new InvalidGrantError("Invalid authorization code");
    }

    return record.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    const record = this.authorizationCodes.get(authorizationCode);
    if (!record || record.clientId !== client.client_id) {
      throw new InvalidGrantError("Invalid authorization code");
    }
    if (redirectUri && redirectUri !== record.redirectUri) {
      throw new InvalidGrantError("redirect_uri does not match");
    }
    if (resource && record.resource && resource.href !== record.resource.href) {
      throw new InvalidGrantError("resource does not match authorization request");
    }

    this.authorizationCodes.delete(authorizationCode);

    const accessToken = createToken();
    const refreshToken = createToken();
    const expiresInSeconds = 3600;
    const expiresAt = Math.floor(Date.now() / 1000) + expiresInSeconds;
    const scopes = record.scopes.length > 0 ? record.scopes : [OAUTH_SCOPE];

    this.accessTokens.set(accessToken, {
      token: accessToken,
      clientId: record.clientId,
      scopes,
      expiresAt,
      extra: {
        perplexityApiKey: record.perplexityApiKey,
      },
    });

    this.refreshTokens.set(refreshToken, {
      clientId: record.clientId,
      scopes,
      resource: record.resource,
      perplexityApiKey: record.perplexityApiKey,
    });

    return {
      access_token: accessToken,
      token_type: "bearer",
      expires_in: expiresInSeconds,
      refresh_token: refreshToken,
      scope: scopes.join(" "),
    };
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    const record = this.refreshTokens.get(refreshToken);
    if (!record || record.clientId !== client.client_id) {
      throw new InvalidGrantError("Invalid refresh token");
    }
    if (resource && record.resource && resource.href !== record.resource.href) {
      throw new InvalidGrantError("resource does not match refresh token");
    }

    const accessToken = createToken();
    const expiresInSeconds = 3600;
    const expiresAt = Math.floor(Date.now() / 1000) + expiresInSeconds;
    const effectiveScopes = scopes && scopes.length > 0 ? scopes : record.scopes;

    this.accessTokens.set(accessToken, {
      token: accessToken,
      clientId: record.clientId,
      scopes: effectiveScopes,
      expiresAt,
      extra: {
        perplexityApiKey: record.perplexityApiKey,
      },
    });

    return {
      access_token: accessToken,
      token_type: "bearer",
      expires_in: expiresInSeconds,
      refresh_token: refreshToken,
      scope: effectiveScopes.join(" "),
    };
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    // Allow direct Perplexity API key usage as Bearer token for compatibility.
    if (token.startsWith("pplx-")) {
      return {
        token,
        clientId: "direct-perplexity-key",
        scopes: [OAUTH_SCOPE],
        expiresAt: Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60,
        extra: {
          perplexityApiKey: token,
        },
      };
    }

    const authInfo = this.accessTokens.get(token);
    if (!authInfo) {
      throw new InvalidTokenError("Invalid access token");
    }
    return authInfo;
  }

  async revokeToken(_client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    this.accessTokens.delete(request.token);
    this.refreshTokens.delete(request.token);
  }

  getPendingAuthorization(requestId: string): PendingAuthorization | undefined {
    return this.pendingAuthorizations.get(requestId);
  }

  completeAuthorization(requestId: string, perplexityApiKey: string): string {
    const pending = this.pendingAuthorizations.get(requestId);
    if (!pending) {
      throw new InvalidGrantError("Unknown authorization request");
    }

    this.pendingAuthorizations.delete(requestId);

    const code = createToken(24);
    this.authorizationCodes.set(code, {
      clientId: pending.clientId,
      redirectUri: pending.params.redirectUri,
      codeChallenge: pending.params.codeChallenge,
      scopes: pending.params.scopes ?? [OAUTH_SCOPE],
      resource: pending.params.resource,
      perplexityApiKey,
    });

    const redirectUrl = new URL(pending.params.redirectUri);
    redirectUrl.searchParams.set("code", code);
    if (pending.params.state) {
      redirectUrl.searchParams.set("state", pending.params.state);
    }

    return redirectUrl.toString();
  }
}

const app = express();
const PORT = parseInt(process.env.PORT || "8080", 10);
const BIND_ADDRESS = process.env.BIND_ADDRESS || "0.0.0.0";
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(",") || ["*"];
const PUBLIC_BASE_URL = process.env.OAUTH_PUBLIC_BASE_URL || `http://127.0.0.1:${PORT}`;
const OAUTH_ISSUER_URL = new URL(process.env.OAUTH_ISSUER_URL || PUBLIC_BASE_URL);
const OAUTH_RESOURCE_SERVER_URL = new URL(process.env.OAUTH_RESOURCE_SERVER_URL || `${PUBLIC_BASE_URL}/mcp`);
const SERVICE_DOCUMENTATION_URL = new URL("https://docs.perplexity.ai/guides/mcp-server");
const oauthProvider = new PerplexityOAuthProvider();
const protectedResourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(OAUTH_RESOURCE_SERVER_URL);

// CORS configuration for browser-based MCP clients
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    
    if (ALLOWED_ORIGINS.includes("*")) {
      return callback(null, true);
    }
    
    if (ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`Origin ${origin} not allowed by CORS`));
    }
  },
  exposedHeaders: ["Mcp-Session-Id", "mcp-protocol-version"],
  allowedHeaders: [
    "Content-Type",
    "mcp-session-id",
    "Authorization",
    "authorization",
    "X-API-Key",
    "x-api-key",
    "X-Perplexity-API-Key",
    "x-perplexity-api-key",
  ],
}));

app.use(express.json());

app.use(
  mcpAuthRouter({
    provider: oauthProvider,
    issuerUrl: OAUTH_ISSUER_URL,
    resourceServerUrl: OAUTH_RESOURCE_SERVER_URL,
    serviceDocumentationUrl: SERVICE_DOCUMENTATION_URL,
    scopesSupported: [OAUTH_SCOPE],
    resourceName: "Perplexity MCP",
  }),
);

app.get("/oauth/consent", (req, res) => {
  const requestId = typeof req.query.request_id === "string" ? req.query.request_id : "";
  const pending = requestId ? oauthProvider.getPendingAuthorization(requestId) : undefined;

  if (!pending) {
    res.status(400).type("text/plain").send("Invalid or expired authorization request");
    return;
  }

  const safeRequestId = escapeHtml(requestId);
  const safeRedirect = escapeHtml(pending.params.redirectUri);
  const safeClientId = escapeHtml(pending.clientId);

  res.status(200).type("html").send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Authorize Perplexity MCP</title>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; max-width: 680px; }
      input { width: 100%; padding: 0.6rem; margin: 0.5rem 0 1rem; font-size: 1rem; }
      button { padding: 0.6rem 1rem; font-size: 1rem; }
      .meta { color: #444; font-size: 0.95rem; }
    </style>
  </head>
  <body>
    <h1>Authorize Perplexity MCP</h1>
    <p class="meta">Client: <strong>${safeClientId}</strong></p>
    <p class="meta">Redirect URI: <strong>${safeRedirect}</strong></p>
    <p>Enter your Perplexity API key to complete OAuth authorization.</p>
    <form method="post" action="/oauth/consent">
      <input type="hidden" name="request_id" value="${safeRequestId}" />
      <label for="api_key">Perplexity API key</label>
      <input id="api_key" name="api_key" placeholder="pplx-..." autocomplete="off" required />
      <button type="submit">Authorize</button>
    </form>
  </body>
</html>`);
});

app.post("/oauth/consent", express.urlencoded({ extended: false }), (req, res) => {
  const requestId = typeof req.body.request_id === "string" ? req.body.request_id : "";
  const apiKey = typeof req.body.api_key === "string" ? req.body.api_key.trim() : "";

  if (!requestId || !apiKey) {
    res.status(400).type("text/plain").send("request_id and api_key are required");
    return;
  }

  try {
    const redirectUrl = oauthProvider.completeAuthorization(requestId, apiKey);
    res.redirect(302, redirectUrl);
  } catch (error) {
    res.status(400).type("text/plain").send(error instanceof Error ? error.message : "Authorization failed");
  }
});

const bearerAuthMiddleware = requireBearerAuth({
  verifier: oauthProvider,
  requiredScopes: [OAUTH_SCOPE],
  resourceMetadataUrl: protectedResourceMetadataUrl,
});

app.use("/mcp", (req, _res, next) => {
  if (!req.headers.authorization) {
    const apiKeyHeader = req.headers["x-api-key"] || req.headers["x-perplexity-api-key"];
    const apiKey = Array.isArray(apiKeyHeader) ? apiKeyHeader[0] : apiKeyHeader;
    if (typeof apiKey === "string" && apiKey.trim()) {
      req.headers.authorization = `Bearer ${apiKey.trim()}`;
    }
  }
  next();
});

app.all("/mcp", bearerAuthMiddleware, async (req, res) => {
  try {
    const mcpServer = createPerplexityServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });

    res.on('close', () => {
      transport.close();
    });

    await mcpServer.connect(transport);
    
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    logger.error("Error handling MCP request", { error: String(error) });
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal server error" },
        id: null,
      });
    }
  }
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "perplexity-mcp-server" });
});

app.listen(PORT, BIND_ADDRESS, () => {
  logger.info(`Perplexity MCP Server listening on http://${BIND_ADDRESS}:${PORT}/mcp`);
  logger.info(`Allowed origins: ${ALLOWED_ORIGINS.join(", ")}`);
  logger.info(`OAuth issuer URL: ${OAUTH_ISSUER_URL.href}`);
  logger.info(`OAuth protected resource metadata URL: ${protectedResourceMetadataUrl}`);
}).on("error", (error) => {
  logger.error("Server error", { error: String(error) });
  process.exit(1);
});

