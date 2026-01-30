/**
 * Vulnerability Tools
 *
 * MCP tools for CrowdStrike Spotlight vulnerability management.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { CrowdStrikeClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

/**
 * Register all vulnerability-related tools
 */
export function registerVulnerabilityTools(server: McpServer, client: CrowdStrikeClient): void {
  // ===========================================================================
  // Query Vulnerabilities
  // ===========================================================================
  server.tool(
    'crowdstrike_query_vulnerabilities',
    `Query vulnerabilities from CrowdStrike Spotlight with filtering.

Note: The filter parameter is REQUIRED for this endpoint.

Args:
  - filter: FQL filter expression (REQUIRED). Examples:
    - "cve.severity:'CRITICAL'"
    - "status:'open'"
    - "cve.exploit_status:>=1" (has known exploits)
    - "host_info.hostname:'server*'"
  - limit: Number of results (1-400, default: 100)
  - after: Pagination cursor for next page
  - sort: Sort field (e.g., "cve.base_score.desc")

Returns:
  Array of vulnerability IDs matching the query.`,
    {
      filter: z.string().describe('FQL filter expression (required)'),
      limit: z.number().int().min(1).max(400).default(100).describe('Number of results'),
      after: z.string().optional().describe('Pagination cursor'),
      sort: z.string().optional().describe('Sort field and direction'),
    },
    async ({ filter, limit, after, sort }) => {
      try {
        const ids = await client.queryVulnerabilities(filter, { limit, after, sort });
        return formatResponse({ ids, count: ids.length }, 'json', 'vulnerability_ids');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Vulnerabilities
  // ===========================================================================
  server.tool(
    'crowdstrike_get_vulnerabilities',
    `Get detailed information for specific vulnerabilities by their IDs.

Args:
  - ids: Array of vulnerability IDs to retrieve (max 400)

Returns:
  Detailed vulnerability information including CVE details, affected hosts, remediation info, and CVSS scores.`,
    {
      ids: z.array(z.string()).min(1).max(400).describe('Vulnerability IDs to retrieve'),
    },
    async ({ ids }) => {
      try {
        const vulnerabilities = await client.getVulnerabilities(ids);
        return formatResponse(vulnerabilities, 'json', 'vulnerabilities');
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
