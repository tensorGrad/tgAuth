export const TENSORGRAD_ISSUER = "https://www.tensorgrad.com";
export const DEFAULT_TG_SCOPES = ["openid", "profile", "email"] as const;

export interface tgOAuthConfig {
  issuer: string;
  clientId: string;
  clientSecret?: string;
}

export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
}

export interface AuthorizationUrlOptions {
  redirectUri: string;
  scope: string[] | string;
  state: string;
  prompt?: "login";
  codeChallenge?: string;
  codeChallengeMethod?: "S256" | "plain";
  extraParams?: Record<string, string>;
}

export interface TokenExchangeOptions {
  issuer: string;
  clientId: string;
  clientSecret?: string;
  code: string;
  redirectUri: string;
  codeVerifier?: string;
  fetchImpl?: typeof fetch;
}

export interface tgTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
  user: tgUserInfo;
}

export interface tgUserInfo {
  sub: string;
  email: string;
  email_verified: boolean;
  name: string | null;
  image: string | null;
}

export interface normalizedTgUser {
  id: string;
  email: string;
  emailVerified: boolean;
  name: string | null;
  image: string | null;
}

const MIN_STATE_BYTES = 16;
const MAX_RANDOM_BYTES = 96;
const MIN_PKCE_RANDOM_BYTES = 32;

const RESERVED_AUTHORIZATION_PARAMS = new Set([
  "client_id",
  "redirect_uri",
  "response_type",
  "scope",
  "state",
  "code_challenge",
  "code_challenge_method"
]);

function requireNonEmptyString(name: string, value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`${name} must be a non-empty string`);
  }

  return trimmed;
}

function assertRandomByteLength(name: string, length: number, min: number, max = MAX_RANDOM_BYTES): void {
  if (!Number.isInteger(length) || length < min || length > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
}

function normalizeIssuer(issuer: string): string {
  const normalized = requireNonEmptyString("issuer", issuer).replace(/\/+$/, "");
  const parsed = new URL(normalized);

  if (!parsed.protocol || !parsed.host) {
    throw new Error("issuer must be an absolute URL");
  }

  return parsed.toString().replace(/\/+$/, "");
}

function normalizeAbsoluteUrl(name: string, value: string): string {
  const normalized = requireNonEmptyString(name, value);
  return new URL(normalized).toString();
}

function parseScopeSet(scope: string[] | string): Set<string> {
  return new Set(
    (Array.isArray(scope) ? scope : scope.split(/\s+/))
      .map((value) => value.trim())
      .filter(Boolean)
  );
}

function normalizeScopeString(scope: string[] | string): string {
  const values = Array.from(parseScopeSet(scope));
  if (values.length === 0) {
    throw new Error("scope must contain at least one value");
  }

  if (!values.includes("openid")) {
    throw new Error("scope must include openid");
  }

  return values.join(" ");
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256(input: string): Promise<Uint8Array> {
  const encoded = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return new Uint8Array(digest);
}

export function createState(length = 32): string {
  assertRandomByteLength("state length", length, MIN_STATE_BYTES);
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return toBase64Url(bytes);
}

export async function createPkcePair(length = 32): Promise<PkcePair> {
  assertRandomByteLength("PKCE length", length, MIN_PKCE_RANDOM_BYTES);
  const verifierBytes = crypto.getRandomValues(new Uint8Array(length));
  const codeVerifier = toBase64Url(verifierBytes);
  const codeChallenge = toBase64Url(await sha256(codeVerifier));

  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: "S256"
  };
}

export function createAuthorizationUrl(
  config: tgOAuthConfig,
  options: AuthorizationUrlOptions
): URL {
  const redirectUri = normalizeAbsoluteUrl("redirectUri", options.redirectUri);
  const state = requireNonEmptyString("state", options.state);
  const scope = normalizeScopeString(options.scope);
  const clientId = requireNonEmptyString("clientId", config.clientId);
  const url = new URL("/oauth/authorize", normalizeIssuer(config.issuer));
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", scope);
  url.searchParams.set("state", state);

  if (options.prompt) {
    url.searchParams.set("prompt", options.prompt);
  }

  if (options.codeChallenge) {
    url.searchParams.set(
      "code_challenge",
      requireNonEmptyString("codeChallenge", options.codeChallenge)
    );
    url.searchParams.set("code_challenge_method", options.codeChallengeMethod ?? "S256");
  }

  for (const [key, value] of Object.entries(options.extraParams ?? {})) {
    if (RESERVED_AUTHORIZATION_PARAMS.has(key)) {
      throw new Error(`extraParams cannot override reserved OAuth parameter: ${key}`);
    }

    url.searchParams.set(key, requireNonEmptyString(`extraParams.${key}`, value));
  }

  return url;
}

async function readJsonOrThrow<T>(response: Response): Promise<T> {
  const text = await response.text();
  let payload: unknown;

  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`Unexpected non-JSON response: ${text}`);
  }

  if (!response.ok) {
    const message =
      typeof payload === "object" &&
      payload !== null &&
      ("error_description" in payload || "error" in payload)
        ? String(
            (payload as Record<string, unknown>).error_description ??
              (payload as Record<string, unknown>).error
          )
        : `HTTP ${response.status}`;
    throw new Error(message);
  }

  return payload as T;
}

export async function exchangeAuthorizationCode(
  options: TokenExchangeOptions
): Promise<tgTokenResponse> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const url = new URL("/oauth/token", normalizeIssuer(options.issuer));
  const body = new URLSearchParams();

  body.set("grant_type", "authorization_code");
  body.set("client_id", requireNonEmptyString("clientId", options.clientId));
  body.set("code", requireNonEmptyString("code", options.code));
  body.set("redirect_uri", normalizeAbsoluteUrl("redirectUri", options.redirectUri));

  if (options.clientSecret) {
    body.set("client_secret", options.clientSecret);
  }

  if (options.codeVerifier) {
    body.set("code_verifier", requireNonEmptyString("codeVerifier", options.codeVerifier));
  }

  const response = await fetchImpl(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });

  return readJsonOrThrow<tgTokenResponse>(response);
}

export async function fetchUserInfo(
  issuer: string,
  accessToken: string,
  fetchImpl: typeof fetch = fetch
): Promise<tgUserInfo> {
  const url = new URL("/oauth/userinfo", normalizeIssuer(issuer));
  const response = await fetchImpl(url, {
    headers: {
      Authorization: `Bearer ${requireNonEmptyString("accessToken", accessToken)}`
    }
  });

  return readJsonOrThrow<tgUserInfo>(response);
}

export function normalizeTgUser(user: tgUserInfo): normalizedTgUser {
  return {
    id: user.sub,
    email: user.email,
    emailVerified: user.email_verified,
    name: user.name,
    image: user.image
  };
}

export function assertGrantedScopes(
  grantedScope: string[] | string,
  requiredScopes: readonly string[]
): void {
  const granted = parseScopeSet(grantedScope);

  const missing = requiredScopes.filter((scope) => !granted.has(scope));
  if (missing.length > 0) {
    throw new Error(`Missing granted scopes: ${missing.join(", ")}`);
  }
}

export function isAdminScopeGranted(grantedScope: string[] | string): boolean {
  return parseScopeSet(grantedScope).has("admin");
}
