/**
 * IOC Tools
 *
 * MCP tools for CrowdStrike Indicator of Compromise (IOC) management.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { CrowdStrikeClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

/**
 * Register all IOC-related tools
 */
export function registerIOCTools(server: McpServer, client: CrowdStrikeClient): void {
  // ===========================================================================
  // Query IOCs
  // ===========================================================================
  server.tool(
    'crowdstrike_query_iocs',
    `Query custom IOCs from CrowdStrike Falcon with optional filtering.

Returns a list of IOC IDs matching the filter criteria. Use crowdstrike_get_iocs to get full details.

Args:
  - filter: FQL filter expression (e.g., "type:'sha256'", "action:'prevent'")
  - limit: Number of results (1-500, default: 100)
  - offset: Pagination offset
  - sort: Sort field (e.g., "created_on.desc")

Returns:
  Array of IOC IDs matching the query.`,
    {
      filter: z.string().optional().describe('FQL filter expression'),
      limit: z.number().int().min(1).max(500).default(100).describe('Number of results'),
      offset: z.number().int().min(0).optional().describe('Pagination offset'),
      sort: z.string().optional().describe('Sort field and direction'),
    },
    async ({ filter, limit, offset, sort }) => {
      try {
        const ids = await client.queryIOCs({ filter, limit, offset, sort });
        return formatResponse({ ids, count: ids.length }, 'json', 'ioc_ids');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get IOCs
  // ===========================================================================
  server.tool(
    'crowdstrike_get_iocs',
    `Get detailed information for specific IOCs by their IDs.

Args:
  - ids: Array of IOC IDs to retrieve

Returns:
  Detailed IOC information including type, value, action, platforms, and metadata.`,
    {
      ids: z.array(z.string()).min(1).describe('IOC IDs to retrieve'),
    },
    async ({ ids }) => {
      try {
        const iocs = await client.getIOCs(ids);
        return formatResponse(iocs, 'json', 'iocs');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create IOC
  // ===========================================================================
  server.tool(
    'crowdstrike_create_ioc',
    `Create a new custom IOC in CrowdStrike Falcon.

Args:
  - type: IOC type (sha256, md5, domain, ipv4, ipv6)
  - value: The indicator value (hash, domain name, or IP address)
  - action: Action to take (no_action, allow, detect, prevent, prevent_no_ui)
  - platforms: Target platforms (windows, mac, linux)
  - severity: Severity level (informational, low, medium, high, critical) - optional
  - description: Description of the IOC - optional
  - tags: Array of tags - optional
  - expiration: Expiration date in ISO format - optional
  - applied_globally: Apply to all hosts (default: true) - optional
  - host_groups: Specific host group IDs (if not applied globally) - optional

Returns:
  The created IOC.`,
    {
      type: z.enum(['sha256', 'md5', 'domain', 'ipv4', 'ipv6']).describe('IOC type'),
      value: z.string().describe('Indicator value'),
      action: z
        .enum(['no_action', 'allow', 'detect', 'prevent', 'prevent_no_ui'])
        .describe('Action to take'),
      platforms: z
        .array(z.enum(['windows', 'mac', 'linux']))
        .min(1)
        .describe('Target platforms'),
      severity: z
        .enum(['informational', 'low', 'medium', 'high', 'critical'])
        .optional()
        .describe('Severity level'),
      description: z.string().optional().describe('Description'),
      tags: z.array(z.string()).optional().describe('Tags'),
      expiration: z.string().optional().describe('Expiration date (ISO format)'),
      applied_globally: z.boolean().optional().default(true).describe('Apply globally'),
      host_groups: z.array(z.string()).optional().describe('Host group IDs'),
    },
    async (input) => {
      try {
        const ioc = await client.createIOC(input);
        return formatResponse(ioc, 'json', 'ioc');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Delete IOCs
  // ===========================================================================
  server.tool(
    'crowdstrike_delete_iocs',
    `Delete one or more custom IOCs from CrowdStrike Falcon.

Args:
  - ids: Array of IOC IDs to delete

Returns:
  Confirmation of deletion.`,
    {
      ids: z.array(z.string()).min(1).describe('IOC IDs to delete'),
    },
    async ({ ids }) => {
      try {
        const result = await client.deleteIOCs(ids);
        return formatResponse(result, 'json', 'delete');
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
