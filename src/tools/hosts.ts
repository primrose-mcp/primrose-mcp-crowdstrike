/**
 * Host Tools
 *
 * MCP tools for CrowdStrike host management.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { CrowdStrikeClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

/**
 * Register all host-related tools
 */
export function registerHostTools(server: McpServer, client: CrowdStrikeClient): void {
  // ===========================================================================
  // Query Hosts
  // ===========================================================================
  server.tool(
    'crowdstrike_query_hosts',
    `Query hosts from CrowdStrike Falcon with optional filtering.

Returns a list of host/device IDs matching the filter criteria. Use crowdstrike_get_hosts to get full details.

Args:
  - filter: FQL filter expression (e.g., "platform_name:'Windows'", "hostname:'workstation*'")
  - limit: Number of results (1-5000, default: 100)
  - offset: Pagination offset
  - sort: Sort field (e.g., "hostname.asc", "last_seen.desc")

Returns:
  Array of device IDs matching the query.`,
    {
      filter: z.string().optional().describe('FQL filter expression'),
      limit: z.number().int().min(1).max(5000).default(100).describe('Number of results'),
      offset: z.number().int().min(0).optional().describe('Pagination offset'),
      sort: z.string().optional().describe('Sort field and direction'),
    },
    async ({ filter, limit, offset, sort }) => {
      try {
        const ids = await client.queryHosts({ filter, limit, offset, sort });
        return formatResponse({ ids, count: ids.length }, 'json', 'host_ids');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Hosts
  // ===========================================================================
  server.tool(
    'crowdstrike_get_hosts',
    `Get detailed information for specific hosts by their device IDs.

Args:
  - ids: Array of device IDs to retrieve (max 100)

Returns:
  Detailed host information including hostname, OS, IP addresses, agent version, policies, etc.`,
    {
      ids: z.array(z.string()).min(1).max(100).describe('Device IDs to retrieve'),
    },
    async ({ ids }) => {
      try {
        const hosts = await client.getHosts(ids);
        return formatResponse(hosts, 'json', 'hosts');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Contain Host
  // ===========================================================================
  server.tool(
    'crowdstrike_contain_host',
    `Network contain one or more hosts. This isolates the host from the network while maintaining Falcon sensor connectivity.

WARNING: This is a critical security action that will cut off network access to the specified hosts.

Args:
  - ids: Array of device IDs to contain (max 100)

Returns:
  Confirmation of containment action.`,
    {
      ids: z.array(z.string()).min(1).max(100).describe('Device IDs to contain'),
    },
    async ({ ids }) => {
      try {
        const result = await client.containHost(ids);
        return formatResponse(result, 'json', 'containment');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Lift Containment
  // ===========================================================================
  server.tool(
    'crowdstrike_lift_containment',
    `Lift network containment from one or more hosts, restoring normal network access.

Args:
  - ids: Array of device IDs to release from containment (max 100)

Returns:
  Confirmation of containment lift action.`,
    {
      ids: z.array(z.string()).min(1).max(100).describe('Device IDs to release'),
    },
    async ({ ids }) => {
      try {
        const result = await client.liftContainment(ids);
        return formatResponse(result, 'json', 'containment');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Hide Host
  // ===========================================================================
  server.tool(
    'crowdstrike_hide_host',
    `Hide one or more hosts from the Falcon console. Hidden hosts are not deleted but are removed from normal views.

Args:
  - ids: Array of device IDs to hide (max 100)

Returns:
  Confirmation of hide action.`,
    {
      ids: z.array(z.string()).min(1).max(100).describe('Device IDs to hide'),
    },
    async ({ ids }) => {
      try {
        const result = await client.hideHost(ids);
        return formatResponse(result, 'json', 'hide');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Unhide Host
  // ===========================================================================
  server.tool(
    'crowdstrike_unhide_host',
    `Unhide one or more previously hidden hosts, making them visible in the Falcon console again.

Args:
  - ids: Array of device IDs to unhide (max 100)

Returns:
  Confirmation of unhide action.`,
    {
      ids: z.array(z.string()).min(1).max(100).describe('Device IDs to unhide'),
    },
    async ({ ids }) => {
      try {
        const result = await client.unhideHost(ids);
        return formatResponse(result, 'json', 'unhide');
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
