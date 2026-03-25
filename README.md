# @tensorgrad/oauth

Small OAuth client SDK for integrating tensorGrad SSO into first-party apps.

## What it does

- creates `state` values
- creates PKCE verifier/challenge pairs
- builds tensorGrad `/oauth/authorize` URLs
- supports `prompt=login` for account switching
- exchanges authorization codes at `/oauth/token`
- fetches canonical identity from `/oauth/userinfo`
- normalizes tensorGrad user payloads
- validates granted scopes

## What it does not do

- manage your app sessions or cookies
- manage roles or permissions inside your app
- assume a frontend framework

## Runtime

This package targets Web API runtimes such as:

- Cloudflare Workers
- modern browsers
- Node runtimes that expose standard Web APIs

## Install

```bash
npm install @tensorgrad/oauth
```

## Core constants

```ts
import { TENSORGRAD_ISSUER } from "@tensorgrad/oauth";

console.log(TENSORGRAD_ISSUER);
// "https://www.tensorgrad.com"
```

## Full Cloudflare Worker example

```ts
import {
  DEFAULT_TG_SCOPES,
  TENSORGRAD_ISSUER,
  assertGrantedScopes,
  createAuthorizationUrl,
  createPkcePair,
  createState,
  exchangeAuthorizationCode,
  fetchUserInfo,
  isAdminScopeGranted,
  normalizeTgUser
} from "@tensorgrad/oauth";

export interface Env {
  TENSORGRAD_CLIENT_ID: string;
  TENSORGRAD_CLIENT_SECRET: string;
}

function html(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/login") {
      const state = createState();
      const pkce = await createPkcePair();
      const redirectUri = `${url.origin}/auth/callback`;

      const authorizeUrl = createAuthorizationUrl(
        {
          issuer: TENSORGRAD_ISSUER,
          clientId: env.TENSORGRAD_CLIENT_ID
        },
        {
          redirectUri,
          scope: DEFAULT_TG_SCOPES,
          state,
          codeChallenge: pkce.codeChallenge,
          codeChallengeMethod: pkce.codeChallengeMethod
        }
      );

      return html(`
        <p><a href="${authorizeUrl.toString()}">Continue with tensorGrad</a></p>
        <p>Persist state and codeVerifier in your own storage before redirecting.</p>
        <pre>${JSON.stringify({ state, codeVerifier: pkce.codeVerifier }, null, 2)}</pre>
      `);
    }

    if (url.pathname === "/auth/callback") {
      const oauthError = url.searchParams.get("error");
      const oauthErrorDescription = url.searchParams.get("error_description");
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");

      if (oauthError) {
        return Response.json(
          {
            error: oauthError,
            errorDescription: oauthErrorDescription ?? null
          },
          { status: 400 }
        );
      }

      if (!code || !state) {
        return new Response("Missing code or state", { status: 400 });
      }

      const redirectUri = `${url.origin}/auth/callback`;

      // Replace these with values loaded from your own storage.
      const expectedState = "<persisted-state>";
      const codeVerifier = "<persisted-code-verifier>";

      // Use a constant-time comparison in your app when comparing secrets.
      if (state !== expectedState) {
        return new Response("Invalid state", { status: 400 });
      }

      const token = await exchangeAuthorizationCode({
        issuer: TENSORGRAD_ISSUER,
        clientId: env.TENSORGRAD_CLIENT_ID,
        clientSecret: env.TENSORGRAD_CLIENT_SECRET,
        code,
        redirectUri,
        codeVerifier
      });

      assertGrantedScopes(token.scope, DEFAULT_TG_SCOPES);

      const userFromToken = normalizeTgUser(token.user);
      const userFromUserInfo = normalizeTgUser(
        await fetchUserInfo(TENSORGRAD_ISSUER, token.access_token)
      );

      return Response.json({
        token,
        userFromToken,
        userFromUserInfo,
        adminGranted: isAdminScopeGranted(token.scope)
      });
    }

    return new Response("Not found", { status: 404 });
  }
};
```

## Notes

- `openid` is mandatory and the library enforces that when building authorize URLs.
- tensorGrad currently uses `https://www.tensorgrad.com` as the OAuth provider.
- `DEFAULT_TG_SCOPES` is the recommended scope set for first-party apps.
- `assertGrantedScopes(token.scope, ["admin"])` is the simplest way to require admin access.
- pass `prompt: "login"` to `createAuthorizationUrl(...)` when you need tensorGrad to force a fresh account selection.
- handle `error` / `error_description` on the callback before validating `code`
- compare persisted `state` values using a constant-time comparison in your app
- `isAdminScopeGranted(token.scope)` is available when you only need a boolean check.
- app session and logout handling stay in the consuming app.
