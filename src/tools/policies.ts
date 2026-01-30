/**
 * Policy Tools
 *
 * MCP tools for CrowdStrike policy management (Prevention, Device Control, Sensor Update).
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { CrowdStrikeClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

/**
 * Register all policy-related tools
 */
export function registerPolicyTools(server: McpServer, client: CrowdStrikeClient): void {
  // ===========================================================================
  // Prevention Policies
  // ===========================================================================
  server.tool(
    'crowdstrike_query_prevention_policies',
    `Query prevention policies from CrowdStrike Falcon.

Prevention policies control endpoint protection behaviors like blocking, quarantining, etc.

Args:
  - filter: FQL filter expression (e.g., "platform_name:'Windows'", "enabled:true")
  - limit: Number of results (1-5000, default: 100)
  - offset: Pagination offset
  - sort: Sort field

Returns:
  Array of prevention policy IDs.`,
    {
      filter: z.string().optional().describe('FQL filter expression'),
      limit: z.number().int().min(1).max(5000).default(100).describe('Number of results'),
      offset: z.number().int().min(0).optional().describe('Pagination offset'),
      sort: z.string().optional().describe('Sort field'),
    },
    async ({ filter, limit, offset, sort }) => {
      try {
        const ids = await client.queryPreventionPolicies({ filter, limit, offset, sort });
        return formatResponse({ ids, count: ids.length }, 'json', 'policy_ids');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'crowdstrike_get_prevention_policies',
    `Get detailed information for specific prevention policies.

Args:
  - ids: Array of policy IDs to retrieve

Returns:
  Detailed policy information including settings, enabled status, and assigned groups.`,
    {
      ids: z.array(z.string()).min(1).describe('Policy IDs to retrieve'),
    },
    async ({ ids }) => {
      try {
        const policies = await client.getPreventionPolicies(ids);
        return formatResponse(policies, 'json', 'policies');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Device Control Policies
  // ===========================================================================
  server.tool(
    'crowdstrike_query_device_control_policies',
    `Query device control policies from CrowdStrike Falcon.

Device control policies manage USB device access and other peripheral controls.

Args:
  - filter: FQL filter expression (e.g., "platform_name:'Windows'")
  - limit: Number of results (1-5000, default: 100)
  - offset: Pagination offset
  - sort: Sort field

Returns:
  Array of device control policy IDs.`,
    {
      filter: z.string().optional().describe('FQL filter expression'),
      limit: z.number().int().min(1).max(5000).default(100).describe('Number of results'),
      offset: z.number().int().min(0).optional().describe('Pagination offset'),
      sort: z.string().optional().describe('Sort field'),
    },
    async ({ filter, limit, offset, sort }) => {
      try {
        const ids = await client.queryDeviceControlPolicies({ filter, limit, offset, sort });
        return formatResponse({ ids, count: ids.length }, 'json', 'policy_ids');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'crowdstrike_get_device_control_policies',
    `Get detailed information for specific device control policies.

Args:
  - ids: Array of policy IDs to retrieve

Returns:
  Detailed policy information including USB/Bluetooth settings and enforcement mode.`,
    {
      ids: z.array(z.string()).min(1).describe('Policy IDs to retrieve'),
    },
    async ({ ids }) => {
      try {
        const policies = await client.getDeviceControlPolicies(ids);
        return formatResponse(policies, 'json', 'policies');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Sensor Update Policies
  // ===========================================================================
  server.tool(
    'crowdstrike_query_sensor_update_policies',
    `Query sensor update policies from CrowdStrike Falcon.

Sensor update policies control Falcon sensor version deployment and update scheduling.

Args:
  - filter: FQL filter expression (e.g., "platform_name:'Windows'")
  - limit: Number of results (1-5000, default: 100)
  - offset: Pagination offset
  - sort: Sort field

Returns:
  Array of sensor update policy IDs.`,
    {
      filter: z.string().optional().describe('FQL filter expression'),
      limit: z.number().int().min(1).max(5000).default(100).describe('Number of results'),
      offset: z.number().int().min(0).optional().describe('Pagination offset'),
      sort: z.string().optional().describe('Sort field'),
    },
    async ({ filter, limit, offset, sort }) => {
      try {
        const ids = await client.querySensorUpdatePolicies({ filter, limit, offset, sort });
        return formatResponse({ ids, count: ids.length }, 'json', 'policy_ids');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'crowdstrike_get_sensor_update_policies',
    `Get detailed information for specific sensor update policies.

Args:
  - ids: Array of policy IDs to retrieve

Returns:
  Detailed policy information including sensor version, build, schedule, and uninstall protection settings.`,
    {
      ids: z.array(z.string()).min(1).describe('Policy IDs to retrieve'),
    },
    async ({ ids }) => {
      try {
        const policies = await client.getSensorUpdatePolicies(ids);
        return formatResponse(policies, 'json', 'policies');
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
