/**
 * Incident Tools
 *
 * MCP tools for CrowdStrike incident management.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { CrowdStrikeClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

/**
 * Register all incident-related tools
 */
export function registerIncidentTools(server: McpServer, client: CrowdStrikeClient): void {
  // ===========================================================================
  // Query Incidents
  // ===========================================================================
  server.tool(
    'crowdstrike_query_incidents',
    `Query incidents from CrowdStrike Falcon with optional filtering.

Returns a list of incident IDs matching the filter criteria. Use crowdstrike_get_incidents to get full details.

Args:
  - filter: FQL filter expression (e.g., "status:20", "fine_score:>=50")
  - limit: Number of results (1-500, default: 100)
  - offset: Pagination offset
  - sort: Sort field (e.g., "start.desc", "fine_score.desc")

Incident Status Values:
  - 20: New
  - 25: Reopened
  - 30: In Progress
  - 40: Closed

Returns:
  Array of incident IDs matching the query.`,
    {
      filter: z.string().optional().describe('FQL filter expression'),
      limit: z.number().int().min(1).max(500).default(100).describe('Number of results'),
      offset: z.number().int().min(0).optional().describe('Pagination offset'),
      sort: z.string().optional().describe('Sort field and direction'),
    },
    async ({ filter, limit, offset, sort }) => {
      try {
        const ids = await client.queryIncidents({ filter, limit, offset, sort });
        return formatResponse({ ids, count: ids.length }, 'json', 'incident_ids');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Incidents
  // ===========================================================================
  server.tool(
    'crowdstrike_get_incidents',
    `Get detailed information for specific incidents by their IDs.

Args:
  - ids: Array of incident IDs to retrieve

Returns:
  Detailed incident information including hosts, tactics, techniques, status, and score.`,
    {
      ids: z.array(z.string()).min(1).describe('Incident IDs to retrieve'),
    },
    async ({ ids }) => {
      try {
        const incidents = await client.getIncidents(ids);
        return formatResponse(incidents, 'json', 'incidents');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Update Incident
  // ===========================================================================
  server.tool(
    'crowdstrike_update_incident',
    `Update an incident by performing an action.

Args:
  - ids: Array of incident IDs to update
  - action: Action to perform (update_status, update_assigned_to_v2, add_tag, delete_tag, add_comment)
  - value: Value for the action (status number, user UUID, tag name, or comment text)

Status Values:
  - 20: New
  - 25: Reopened
  - 30: In Progress
  - 40: Closed

Returns:
  Confirmation of update action.`,
    {
      ids: z.array(z.string()).min(1).describe('Incident IDs to update'),
      action: z
        .enum(['update_status', 'update_assigned_to_v2', 'add_tag', 'delete_tag', 'add_comment'])
        .describe('Action to perform'),
      value: z.string().describe('Value for the action'),
    },
    async ({ ids, action, value }) => {
      try {
        const result = await client.updateIncident(ids, action, value);
        return formatResponse(result, 'json', 'update');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Behaviors
  // ===========================================================================
  server.tool(
    'crowdstrike_get_behaviors',
    `Get detailed information about specific behaviors by their IDs.

Behaviors are the individual suspicious activities that make up detections and incidents.

Args:
  - ids: Array of behavior IDs to retrieve

Returns:
  Detailed behavior information including command lines, file info, IOCs, and MITRE mappings.`,
    {
      ids: z.array(z.string()).min(1).describe('Behavior IDs to retrieve'),
    },
    async ({ ids }) => {
      try {
        const behaviors = await client.getBehaviors(ids);
        return formatResponse(behaviors, 'json', 'behaviors');
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
