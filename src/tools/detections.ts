/**
 * Detection Tools
 *
 * MCP tools for CrowdStrike detection management.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { CrowdStrikeClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

/**
 * Register all detection-related tools
 */
export function registerDetectionTools(server: McpServer, client: CrowdStrikeClient): void {
  // ===========================================================================
  // Query Detections
  // ===========================================================================
  server.tool(
    'crowdstrike_query_detections',
    `Query detections from CrowdStrike Falcon with optional filtering.

Returns a list of detection IDs matching the filter criteria. Use crowdstrike_get_detections to get full details.

Args:
  - filter: FQL filter expression (e.g., "status:'new'", "max_severity_displayname:'Critical'")
  - limit: Number of results (1-9999, default: 100)
  - offset: Pagination offset
  - sort: Sort field (e.g., "first_behavior.desc", "max_severity.desc")

Returns:
  Array of detection IDs matching the query.`,
    {
      filter: z.string().optional().describe('FQL filter expression'),
      limit: z.number().int().min(1).max(9999).default(100).describe('Number of results'),
      offset: z.number().int().min(0).optional().describe('Pagination offset'),
      sort: z.string().optional().describe('Sort field and direction'),
    },
    async ({ filter, limit, offset, sort }) => {
      try {
        const ids = await client.queryDetections({ filter, limit, offset, sort });
        return formatResponse({ ids, count: ids.length }, 'json', 'detection_ids');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Detections
  // ===========================================================================
  server.tool(
    'crowdstrike_get_detections',
    `Get detailed information for specific detections by their IDs.

Args:
  - ids: Array of detection IDs to retrieve (max 1000)

Returns:
  Detailed detection information including behaviors, device info, severity, status, and more.`,
    {
      ids: z.array(z.string()).min(1).max(1000).describe('Detection IDs to retrieve'),
    },
    async ({ ids }) => {
      try {
        const detections = await client.getDetections(ids);
        return formatResponse(detections, 'json', 'detections');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Update Detection Status
  // ===========================================================================
  server.tool(
    'crowdstrike_update_detection',
    `Update the status and assignment of one or more detections.

Args:
  - ids: Array of detection IDs to update
  - status: New status (new, in_progress, true_positive, false_positive, ignored)
  - assigned_to_uuid: UUID of user to assign (optional)
  - comment: Comment to add (optional)

Returns:
  Confirmation of update action.`,
    {
      ids: z.array(z.string()).min(1).describe('Detection IDs to update'),
      status: z
        .enum(['new', 'in_progress', 'true_positive', 'false_positive', 'ignored'])
        .describe('New status'),
      assigned_to_uuid: z.string().optional().describe('User UUID to assign'),
      comment: z.string().optional().describe('Comment to add'),
    },
    async ({ ids, status, assigned_to_uuid, comment }) => {
      try {
        const result = await client.updateDetectionStatus(ids, status, assigned_to_uuid, comment);
        return formatResponse(result, 'json', 'update');
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
