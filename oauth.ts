// Minimal OAuth 2.1 authorization server shim, so remote MCP clients that require an OAuth
// handshake (e.g. Claude.ai custom connectors) can connect to this server, gated by the same
// shared secret (MCP_AUTH_TOKEN) used for plain bearer-token auth.
//
// This is NOT a general-purpose OAuth server: there is no real user identity, just a single
// shared secret entered once in a browser form. Dynamic client registration, code/token issuance,
// and PKCE verification are all handled by the MCP SDK's own building blocks
// (DemoInMemoryAuthProvider + mcpAuthRouter); the only custom piece is the /authorize login form
// that gates access behind the shared secret, since the SDK's demo provider auto-approves.
import { timingSafeEqual } from "crypto";
import type { Application, Request, Response, NextFunction } from "express";
import express from "express";
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { DemoInMemoryAuthProvider } from "@modelcontextprotocol/sdk/examples/server/demoInMemoryOAuthProvider.js";
import type { AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

function constantTimeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    timingSafeEqual(bufB, bufB);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string));
}

// Adds a shared-secret login gate in front of the SDK demo provider's `authorize`, which
// otherwise "simulates a user login" and always approves immediately.
class SharedSecretOAuthProvider extends DemoInMemoryAuthProvider {
  constructor(private readonly authToken: string | undefined) {
    super();
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    if (!this.authToken) {
      await super.authorize(client, params, res);
      return;
    }
    res.status(200).type("html").send(renderLoginForm(client, params));
  }

  // Bypasses the secret check - called only after the login form's POST has already verified it.
  async completeAuthorization(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    await super.authorize(client, params, res);
  }

  checkSecret(provided: string | undefined): boolean {
    if (!this.authToken) return true;
    return !!provided && constantTimeEquals(provided, this.authToken);
  }
}

function renderLoginForm(client: OAuthClientInformationFull, params: AuthorizationParams, error?: string): string {
  const clientName = escapeHtml(client.client_name || client.client_id);
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Authorize ${clientName}</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 420px; margin: 4rem auto; padding: 0 1rem; }
  h1 { font-size: 1.25rem; }
  input[type=password] { width: 100%; padding: 0.5rem; font-size: 1rem; box-sizing: border-box; }
  button { margin-top: 1rem; padding: 0.5rem 1.5rem; font-size: 1rem; cursor: pointer; }
  .error { color: #b00020; margin-top: 0.5rem; }
</style></head>
<body>
  <h1>${clientName} wants to connect</h1>
  <p>Enter the server's access token to authorize this connection.</p>
  <form method="POST" action="/authorize">
    <input type="hidden" name="client_id" value="${escapeHtml(client.client_id)}">
    <input type="hidden" name="redirect_uri" value="${escapeHtml(params.redirectUri)}">
    <input type="hidden" name="response_type" value="code">
    <input type="hidden" name="code_challenge" value="${escapeHtml(params.codeChallenge)}">
    <input type="hidden" name="code_challenge_method" value="S256">
    <input type="hidden" name="scope" value="${escapeHtml((params.scopes ?? []).join(" "))}">
    <input type="hidden" name="state" value="${escapeHtml(params.state ?? "")}">
    <input type="hidden" name="resource" value="${escapeHtml(params.resource?.toString() ?? "")}">
    <input type="password" name="token" placeholder="Access token" autofocus required>
    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ""}
    <button type="submit">Authorize</button>
  </form>
</body></html>`;
}

// client_id/redirect_uri/response_type/code_challenge validation shared by GET and POST /authorize.
function readAuthorizeRequest(source: Record<string, unknown>) {
  const client_id = typeof source.client_id === "string" ? source.client_id : undefined;
  const redirect_uri = typeof source.redirect_uri === "string" ? source.redirect_uri : undefined;
  const response_type = typeof source.response_type === "string" ? source.response_type : undefined;
  const code_challenge = typeof source.code_challenge === "string" ? source.code_challenge : undefined;
  const code_challenge_method = typeof source.code_challenge_method === "string" ? source.code_challenge_method : undefined;
  const scope = typeof source.scope === "string" ? source.scope : undefined;
  const state = typeof source.state === "string" ? source.state : undefined;
  const resource = typeof source.resource === "string" && source.resource ? source.resource : undefined;
  const token = typeof source.token === "string" ? source.token : undefined;

  if (!client_id) throw new Error("client_id is required");
  if (!redirect_uri) throw new Error("redirect_uri is required");
  if (response_type !== "code") throw new Error("response_type must be 'code'");
  if (!code_challenge) throw new Error("code_challenge is required");
  if (code_challenge_method !== "S256") throw new Error("code_challenge_method must be 'S256'");

  return { client_id, redirect_uri, code_challenge, scope, state, resource, token };
}

export interface OAuthShimOptions {
  app: Application;
  issuerUrl: URL;
  resourceServerUrl: URL;
  authToken: string | undefined;
}

// Installs discovery metadata, dynamic client registration, a browser-based authorize/login
// flow, and the token endpoint. Returns middleware that enforces the resulting bearer tokens.
export function installOAuthShim({ app, issuerUrl, resourceServerUrl, authToken }: OAuthShimOptions): (req: Request, res: Response, next: NextFunction) => void {
  const provider = new SharedSecretOAuthProvider(authToken);
  const bodyParser = express.urlencoded({ extended: false });

  // Registered ahead of mcpAuthRouter below, so these take precedence over its built-in
  // /authorize handler (which has no concept of our shared-secret gate).
  app.get("/authorize", async (req: Request, res: Response) => {
    try {
      const parsed = readAuthorizeRequest(req.query as Record<string, unknown>);
      const client = await provider.clientsStore.getClient(parsed.client_id);
      if (!client) {
        res.status(400).send("Unknown client_id");
        return;
      }
      if (!client.redirect_uris.includes(parsed.redirect_uri)) {
        res.status(400).send("Unregistered redirect_uri");
        return;
      }
      const params: AuthorizationParams = {
        state: parsed.state,
        scopes: parsed.scope ? parsed.scope.split(" ") : [],
        codeChallenge: parsed.code_challenge,
        redirectUri: parsed.redirect_uri,
        resource: parsed.resource ? new URL(parsed.resource) : undefined,
      };
      await provider.authorize(client, params, res);
    } catch (error) {
      res.status(400).send(`Bad authorization request: ${error}`);
    }
  });

  app.post("/authorize", bodyParser, async (req: Request, res: Response) => {
    try {
      const parsed = readAuthorizeRequest(req.body as Record<string, unknown>);
      const client = await provider.clientsStore.getClient(parsed.client_id);
      if (!client) {
        res.status(400).send("Unknown client_id");
        return;
      }
      if (!client.redirect_uris.includes(parsed.redirect_uri)) {
        res.status(400).send("Unregistered redirect_uri");
        return;
      }
      const params: AuthorizationParams = {
        state: parsed.state,
        scopes: parsed.scope ? parsed.scope.split(" ") : [],
        codeChallenge: parsed.code_challenge,
        redirectUri: parsed.redirect_uri,
        resource: parsed.resource ? new URL(parsed.resource) : undefined,
      };
      if (!provider.checkSecret(parsed.token)) {
        res.status(401).type("html").send(renderLoginForm(client, params, "Incorrect access token. Try again."));
        return;
      }
      await provider.completeAuthorization(client, params, res);
    } catch (error) {
      res.status(400).send(`Bad authorization request: ${error}`);
    }
  });

  // Handles discovery metadata, dynamic client registration (/register), and the token endpoint
  // (/token) - only its own /authorize wiring is shadowed by the routes registered above.
  app.use(
    mcpAuthRouter({
      provider,
      issuerUrl,
      resourceServerUrl,
      scopesSupported: ["mcp"],
      resourceName: "Windows Command Line MCP Server",
    })
  );

  return requireBearerAuth({
    verifier: provider,
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(resourceServerUrl),
  });
}
