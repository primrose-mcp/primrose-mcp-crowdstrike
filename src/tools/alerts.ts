/**
 * Alert Tools
 *
 * MCP tools for CrowdStrike alert management.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { CrowdStrikeClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

/**
 * Register all alert-related tools
 */
export function registerAlertTools(server: McpServer, client: CrowdStrikeClient): void {
  // ===========================================================================
  // Query Alerts
  // ===========================================================================
  server.tool(
    'crowdstrike_query_alerts',
    `Query alerts from CrowdStrike Falcon with optional filtering.

Alerts are unified security notifications that can come from various CrowdStrike products.

Args:
  - filter: FQL filter expression (e.g., "severity:>=3", "status:'new'")
  - limit: Number of results (1-10000, default: 100)
  - offset: Pagination offset
  - sort: Sort field (e.g., "created_timestamp.desc")

Returns:
  Array of alert IDs matching the query.`,
    {
      filter: z.string().optional().describe('FQL filter expression'),
      limit: z.number().int().min(1).max(10000).default(100).describe('Number of results'),
      offset: z.number().int().min(0).optional().describe('Pagination offset'),
      sort: z.string().optional().describe('Sort field and direction'),
    },
    async ({ filter, limit, offset, sort }) => {
      try {
        const ids = await client.queryAlerts({ filter, limit, offset, sort });
        return formatResponse({ ids, count: ids.length }, 'json', 'alert_ids');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Alerts
  // ===========================================================================
  server.tool(
    'crowdstrike_get_alerts',
    `Get detailed information for specific alerts by their IDs.

Args:
  - ids: Array of alert IDs (composite_ids) to retrieve

Returns:
  Detailed alert information including severity, status, device info, and behaviors.`,
    {
      ids: z.array(z.string()).min(1).describe('Alert IDs to retrieve'),
    },
    async ({ ids }) => {
      try {
        const alerts = await client.getAlerts(ids);
        return formatResponse(alerts, 'json', 'alerts');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Update Alerts
  // ===========================================================================
  server.tool(
    'crowdstrike_update_alerts',
    `Update the status and assignment of one or more alerts.

Args:
  - ids: Array of alert IDs to update
  - status: New status (optional)
  - assigned_to: User UUID to assign (optional)
  - comment: Comment to add (optional)

Returns:
  Confirmation of update action.`,
    {
      ids: z.array(z.string()).min(1).describe('Alert IDs to update'),
      status: z.string().optional().describe('New status'),
      assigned_to: z.string().optional().describe('User UUID to assign'),
      comment: z.string().optional().describe('Comment to add'),
    },
    async ({ ids, status, assigned_to, comment }) => {
      try {
        const result = await client.updateAlerts(ids, status, assigned_to, comment);
        return formatResponse(result, 'json', 'update');
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
