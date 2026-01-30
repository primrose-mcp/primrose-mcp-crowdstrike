/**
 * CrowdStrike Falcon MCP Server - Main Entry Point
 *
 * This file sets up the MCP server using Cloudflare's Agents SDK.
 * It supports both stateless (McpServer) and stateful (McpAgent) modes.
 *
 * MULTI-TENANT ARCHITECTURE:
 * Tenant credentials (OAuth2 client ID/secret) are parsed from request headers,
 * allowing a single server deployment to serve multiple customers.
 *
 * Required Headers:
 * - X-CrowdStrike-Client-ID: OAuth2 Client ID
 * - X-CrowdStrike-Client-Secret: OAuth2 Client Secret
 *
 * Optional Headers:
 * - X-CrowdStrike-Base-URL: Override the default API base URL
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpAgent } from 'agents/mcp';
import { createCrowdStrikeClient } from './client.js';
import {
  registerAlertTools,
  registerDetectionTools,
  registerHostGroupTools,
  registerHostTools,
  registerIncidentTools,
  registerIOCTools,
  registerPolicyTools,
  registerRTRTools,
  registerVulnerabilityTools,
} from './tools/index.js';
import {
  type Env,
  type TenantCredentials,
  parseTenantCredentials,
  validateCredentials,
} from './types/env.js';

// =============================================================================
// MCP Server Configuration
// =============================================================================

const SERVER_NAME = 'primrose-mcp-crowdstrike';
const SERVER_VERSION = '1.0.0';

// =============================================================================
// MCP Agent (Stateful - uses Durable Objects)
// =============================================================================

/**
 * McpAgent provides stateful MCP sessions backed by Durable Objects.
 *
 * NOTE: For multi-tenant deployments, use the stateless mode instead.
 * The stateful McpAgent is better suited for single-tenant deployments where
 * credentials can be stored as wrangler secrets.
 *
 * @deprecated For multi-tenant support, use stateless mode with per-request credentials
 */
export class CrowdStrikeMcpAgent extends McpAgent<Env> {
  server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  async init() {
    throw new Error(
      'Stateful mode (McpAgent) is not supported for multi-tenant deployments. ' +
        'Use the stateless /mcp endpoint with X-CrowdStrike-Client-ID and X-CrowdStrike-Client-Secret headers instead.'
    );
  }
}

// =============================================================================
// Stateless MCP Server (Recommended - no Durable Objects needed)
// =============================================================================

/**
 * Creates a stateless MCP server instance with tenant-specific credentials.
 *
 * MULTI-TENANT: Each request provides credentials via headers, allowing
 * a single server deployment to serve multiple tenants.
 *
 * @param credentials - Tenant credentials parsed from request headers
 */
function createStatelessServer(credentials: TenantCredentials): McpServer {
  const server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  // Create client with tenant-specific credentials
  const client = createCrowdStrikeClient(credentials);

  // Register all CrowdStrike tools
  registerHostTools(server, client);
  registerDetectionTools(server, client);
  registerIncidentTools(server, client);
  registerAlertTools(server, client);
  registerIOCTools(server, client);
  registerVulnerabilityTools(server, client);
  registerHostGroupTools(server, client);
  registerPolicyTools(server, client);
  registerRTRTools(server, client);

  // Test connection tool
  server.tool(
    'crowdstrike_test_connection',
    'Test the connection to the CrowdStrike Falcon API',
    {},
    async () => {
      try {
        const result = await client.testConnection();
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: `Connection failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  return server;
}

// =============================================================================
// Worker Export
// =============================================================================

export default {
  /**
   * Main fetch handler for the Worker
   */
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Health check endpoint
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok', server: SERVER_NAME }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // ==========================================================================
    // Stateless MCP with Streamable HTTP (Recommended for multi-tenant)
    // ==========================================================================
    if (url.pathname === '/mcp' && request.method === 'POST') {
      // Parse tenant credentials from request headers
      const credentials = parseTenantCredentials(request);

      // Validate credentials are present
      try {
        validateCredentials(credentials);
      } catch (error) {
        return new Response(
          JSON.stringify({
            error: 'Unauthorized',
            message: error instanceof Error ? error.message : 'Invalid credentials',
            required_headers: ['X-CrowdStrike-Client-ID', 'X-CrowdStrike-Client-Secret'],
          }),
          {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
          }
        );
      }

      // Create server with tenant-specific credentials
      const server = createStatelessServer(credentials);

      // Import and use createMcpHandler for streamable HTTP
      const { createMcpHandler } = await import('agents/mcp');
      const handler = createMcpHandler(server);
      return handler(request, env, ctx);
    }

    // SSE endpoint for legacy clients
    if (url.pathname === '/sse') {
      return new Response('SSE endpoint requires Durable Objects. Enable in wrangler.jsonc.', {
        status: 501,
      });
    }

    // Default response
    return new Response(
      JSON.stringify({
        name: SERVER_NAME,
        version: SERVER_VERSION,
        description: 'CrowdStrike Falcon MCP Server - Multi-tenant security operations',
        endpoints: {
          mcp: '/mcp (POST) - Streamable HTTP MCP endpoint',
          health: '/health - Health check',
        },
        authentication: {
          description: 'Pass tenant credentials via request headers',
          required_headers: {
            'X-CrowdStrike-Client-ID': 'OAuth2 Client ID from CrowdStrike API Clients page',
            'X-CrowdStrike-Client-Secret': 'OAuth2 Client Secret',
          },
          optional_headers: {
            'X-CrowdStrike-Base-URL':
              'Override API base URL (default: api.crowdstrike.com). Regional options: api.us-2.crowdstrike.com, api.eu-1.crowdstrike.com, etc.',
          },
        },
        available_tools: [
          'crowdstrike_test_connection',
          'crowdstrike_query_hosts',
          'crowdstrike_get_hosts',
          'crowdstrike_contain_host',
          'crowdstrike_lift_containment',
          'crowdstrike_hide_host',
          'crowdstrike_unhide_host',
          'crowdstrike_query_detections',
          'crowdstrike_get_detections',
          'crowdstrike_update_detection',
          'crowdstrike_query_incidents',
          'crowdstrike_get_incidents',
          'crowdstrike_update_incident',
          'crowdstrike_get_behaviors',
          'crowdstrike_query_alerts',
          'crowdstrike_get_alerts',
          'crowdstrike_update_alerts',
          'crowdstrike_query_iocs',
          'crowdstrike_get_iocs',
          'crowdstrike_create_ioc',
          'crowdstrike_delete_iocs',
          'crowdstrike_query_vulnerabilities',
          'crowdstrike_get_vulnerabilities',
          'crowdstrike_query_host_groups',
          'crowdstrike_get_host_groups',
          'crowdstrike_create_host_group',
          'crowdstrike_update_host_group',
          'crowdstrike_delete_host_groups',
          'crowdstrike_add_hosts_to_group',
          'crowdstrike_remove_hosts_from_group',
          'crowdstrike_query_prevention_policies',
          'crowdstrike_get_prevention_policies',
          'crowdstrike_query_device_control_policies',
          'crowdstrike_get_device_control_policies',
          'crowdstrike_query_sensor_update_policies',
          'crowdstrike_get_sensor_update_policies',
          'crowdstrike_init_rtr_session',
          'crowdstrike_rtr_command',
          'crowdstrike_rtr_active_responder_command',
          'crowdstrike_delete_rtr_session',
        ],
      }),
      {
        headers: { 'Content-Type': 'application/json' },
      }
    );
  },
};
