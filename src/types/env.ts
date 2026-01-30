/**
 * Environment Bindings
 *
 * Type definitions for Cloudflare Worker environment variables and bindings.
 *
 * MULTI-TENANT ARCHITECTURE:
 * This server supports multiple tenants. Tenant-specific credentials (OAuth2
 * client ID/secret) are passed via request headers, NOT stored in wrangler
 * secrets. This allows a single server instance to serve multiple customers.
 *
 * Required Request Headers:
 * - X-CrowdStrike-Client-ID: OAuth2 Client ID
 * - X-CrowdStrike-Client-Secret: OAuth2 Client Secret
 *
 * Optional Request Headers:
 * - X-CrowdStrike-Base-URL: Override the default API base URL
 */

// =============================================================================
// Tenant Credentials (parsed from request headers)
// =============================================================================

export interface TenantCredentials {
  /** OAuth2 Client ID (from X-CrowdStrike-Client-ID header) */
  clientId: string;

  /** OAuth2 Client Secret (from X-CrowdStrike-Client-Secret header) */
  clientSecret: string;

  /** Override API base URL (from X-CrowdStrike-Base-URL header) */
  baseUrl?: string;
}

/**
 * Parse tenant credentials from request headers
 */
export function parseTenantCredentials(request: Request): TenantCredentials {
  const headers = request.headers;

  return {
    clientId: headers.get('X-CrowdStrike-Client-ID') || '',
    clientSecret: headers.get('X-CrowdStrike-Client-Secret') || '',
    baseUrl: headers.get('X-CrowdStrike-Base-URL') || undefined,
  };
}

/**
 * Validate that required credentials are present
 */
export function validateCredentials(credentials: TenantCredentials): void {
  if (!credentials.clientId || !credentials.clientSecret) {
    throw new Error(
      'Missing credentials. Provide both X-CrowdStrike-Client-ID and X-CrowdStrike-Client-Secret headers.'
    );
  }
}

// =============================================================================
// Environment Configuration (from wrangler.jsonc vars and bindings)
// =============================================================================

export interface Env {
  // ===========================================================================
  // Environment Variables (from wrangler.jsonc vars)
  // ===========================================================================

  /** Maximum character limit for responses */
  CHARACTER_LIMIT: string;

  /** Default page size for list operations */
  DEFAULT_PAGE_SIZE: string;

  /** Maximum page size allowed */
  MAX_PAGE_SIZE: string;

  // ===========================================================================
  // Bindings
  // ===========================================================================

  /** KV namespace for OAuth token storage */
  OAUTH_KV?: KVNamespace;

  /** Durable Object namespace for MCP sessions */
  MCP_SESSIONS?: DurableObjectNamespace;

  /** Cloudflare AI binding (optional) */
  AI?: Ai;
}

// ===========================================================================
// Helper Functions
// ===========================================================================

/**
 * Get a numeric environment value with a default
 */
export function getEnvNumber(env: Env, key: keyof Env, defaultValue: number): number {
  const value = env[key];
  if (typeof value === 'string') {
    const parsed = parseInt(value, 10);
    return Number.isNaN(parsed) ? defaultValue : parsed;
  }
  return defaultValue;
}

/**
 * Get the character limit from environment
 */
export function getCharacterLimit(env: Env): number {
  return getEnvNumber(env, 'CHARACTER_LIMIT', 50000);
}

/**
 * Get the default page size from environment
 */
export function getDefaultPageSize(env: Env): number {
  return getEnvNumber(env, 'DEFAULT_PAGE_SIZE', 100);
}

/**
 * Get the maximum page size from environment
 */
export function getMaxPageSize(env: Env): number {
  return getEnvNumber(env, 'MAX_PAGE_SIZE', 5000);
}
