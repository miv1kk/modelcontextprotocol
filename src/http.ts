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

  res.status(200).type("html").send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Authorize Perplexity MCP</title>
    <style>
      :root {
        color-scheme: dark;
        --bg: #060606;
        --line: rgba(255, 255, 255, 0.22);
        --line-strong: rgba(255, 255, 255, 0.98);
        --neon: rgba(255, 255, 255, 0.96);
        --text: #f5f5f5;
        --text-soft: #bdbdbd;
      }

      * { box-sizing: border-box; }

      html, body {
        width: 100%;
        height: 100%;
        margin: 0;
        font-family: "Segoe UI", "SF Pro Text", -apple-system, BlinkMacSystemFont, sans-serif;
        background:
          radial-gradient(1100px 460px at 50% -18%, rgba(255, 255, 255, 0.11), transparent 62%),
          radial-gradient(760px 420px at 8% 100%, rgba(255, 255, 255, 0.05), transparent 66%),
          var(--bg);
        color: var(--text);
        overflow: hidden;
      }

      body::before {
        content: "";
        position: fixed;
        inset: -20%;
        pointer-events: none;
        background: radial-gradient(closest-side, rgba(255, 255, 255, 0.04), transparent 72%);
      }

      .screen {
        min-height: 100%;
        display: grid;
        place-items: center;
        padding: 26px;
      }

      .card {
        position: relative;
        width: min(560px, 100%);
        background: linear-gradient(180deg, rgba(20, 20, 20, 0.94), rgba(8, 8, 8, 0.92));
        border: 1px solid var(--line);
        border-radius: 26px;
        padding: 30px 24px 22px;
        box-shadow:
          0 0 0 1px rgba(255, 255, 255, 0.1),
          0 18px 60px rgba(0, 0, 0, 0.62),
          0 0 30px rgba(255, 255, 255, 0.12);
        overflow: hidden;
      }

      .card::before {
        content: "";
        position: absolute;
        inset: 1px;
        pointer-events: none;
        border-radius: 24px;
        border: 1px solid rgba(255, 255, 255, 0.08);
      }

      .card::after {
        content: "";
        position: absolute;
        inset: 0;
        padding: 1.5px;
        pointer-events: none;
        border-radius: 26px;
        background:
          linear-gradient(120deg,
            rgba(255, 255, 255, 0.95) 0%,
            rgba(255, 255, 255, 0.48) 24%,
            rgba(255, 255, 255, 0.78) 49%,
            rgba(255, 255, 255, 0.48) 74%,
            rgba(255, 255, 255, 0.94) 100%);
        -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
        -webkit-mask-composite: xor;
        mask-composite: exclude;
        filter: drop-shadow(0 0 6px var(--neon)) drop-shadow(0 0 18px rgba(255, 255, 255, 0.28));
        opacity: 0.96;
      }

      h1 {
        margin: 0;
        font-size: clamp(1.35rem, 3vw, 1.85rem);
        letter-spacing: 0.03em;
      }

      .subtitle {
        margin: 10px 0 18px;
        color: var(--text-soft);
        font-size: 0.98rem;
      }

      .field-label {
        display: block;
        margin: 0 0 8px;
        font-size: 0.9rem;
      }

      .input-wrap {
        display: flex;
        gap: 8px;
      }

      .input-wrap input {
        flex: 1;
        min-width: 0;
      }

      input {
        width: 100%;
        border: 1px solid rgba(255, 255, 255, 0.28);
        border-radius: 12px;
        background: rgba(0, 0, 0, 0.66);
        color: #fff;
        padding: 0.76rem 0.84rem;
        font-size: 0.96rem;
        outline: none;
        transition: border-color 220ms ease, box-shadow 220ms ease, background-color 220ms ease;
      }

      input:focus {
        border-color: #fff;
        background: rgba(0, 0, 0, 0.78);
        box-shadow: 0 0 0 2px rgba(255, 255, 255, 0.26), 0 0 18px rgba(255, 255, 255, 0.3);
      }

      .ghost {
        border: 1px solid rgba(255, 255, 255, 0.28);
        border-radius: 12px;
        background: rgba(255, 255, 255, 0.02);
        color: #eaeaea;
        padding: 0 12px;
        cursor: pointer;
        font-size: 0.86rem;
        transition: border-color 180ms ease, box-shadow 180ms ease, background-color 180ms ease;
      }

      .ghost:hover {
        border-color: rgba(255, 255, 255, 0.95);
        background: rgba(255, 255, 255, 0.06);
        box-shadow: 0 0 12px rgba(255, 255, 255, 0.24);
      }

      .submit {
        width: 100%;
        margin-top: 12px;
        border: 1px solid #fff;
        border-radius: 12px;
        background: linear-gradient(180deg, #ffffff 0%, #ececec 100%);
        color: #050505;
        font-weight: 600;
        font-size: 0.96rem;
        padding: 0.78rem 0.95rem;
        cursor: pointer;
        transition: transform 160ms ease, box-shadow 220ms ease, opacity 220ms ease, filter 220ms ease;
      }

      .submit:hover {
        filter: brightness(1.06);
        box-shadow: 0 0 20px rgba(255, 255, 255, 0.64), 0 0 34px rgba(255, 255, 255, 0.34);
      }

      .submit:active {
        transform: translateY(1px);
      }

      .hint {
        margin: 10px 0 0;
        color: #999;
        font-size: 0.82rem;
      }

      @media (max-width: 640px) {
        .screen { padding: 14px; }
        .card { padding: 22px 16px 16px; }
      }
    </style>
  </head>
  <body>
    <main class="screen">
      <section class="card">
        <h1>Authorize Perplexity MCP</h1>
        <p class="subtitle">Enter your API key to finish OAuth authorization.</p>

        <form method="post" action="/oauth/consent">
          <input type="hidden" name="request_id" value="${safeRequestId}" />
          <label class="field-label" for="api_key">Perplexity API key</label>
          <div class="input-wrap">
            <input id="api_key" name="api_key" type="password" placeholder="pplx-..." autocomplete="off" required />
            <button class="ghost" type="button" id="toggle-key" aria-label="Show key">Show</button>
          </div>
          <button class="submit" type="submit">Continue</button>
          <p class="hint">Your key is attached to the OAuth token metadata for this MCP session.</p>
        </form>
      </section>
    </main>

    <script>
      (function () {
        var input = document.getElementById("api_key");
        var toggle = document.getElementById("toggle-key");
        if (!input || !toggle) return;

        toggle.addEventListener("click", function () {
          var isHidden = input.getAttribute("type") === "password";
          input.setAttribute("type", isHidden ? "text" : "password");
          toggle.textContent = isHidden ? "Hide" : "Show";
        });
      })();
    </script>
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

