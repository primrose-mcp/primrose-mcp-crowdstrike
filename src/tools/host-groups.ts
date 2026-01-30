/**
 * Host Group Tools
 *
 * MCP tools for CrowdStrike host group management.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { CrowdStrikeClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

/**
 * Register all host group-related tools
 */
export function registerHostGroupTools(server: McpServer, client: CrowdStrikeClient): void {
  // ===========================================================================
  // Query Host Groups
  // ===========================================================================
  server.tool(
    'crowdstrike_query_host_groups',
    `Query host groups from CrowdStrike Falcon with optional filtering.

Returns a list of host group IDs matching the filter criteria.

Args:
  - filter: FQL filter expression (e.g., "name:'Production*'", "group_type:'dynamic'")
  - limit: Number of results (1-500, default: 100)
  - offset: Pagination offset
  - sort: Sort field (e.g., "name.asc", "created_timestamp.desc")

Returns:
  Array of host group IDs matching the query.`,
    {
      filter: z.string().optional().describe('FQL filter expression'),
      limit: z.number().int().min(1).max(500).default(100).describe('Number of results'),
      offset: z.number().int().min(0).optional().describe('Pagination offset'),
      sort: z.string().optional().describe('Sort field and direction'),
    },
    async ({ filter, limit, offset, sort }) => {
      try {
        const ids = await client.queryHostGroups({ filter, limit, offset, sort });
        return formatResponse({ ids, count: ids.length }, 'json', 'host_group_ids');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Host Groups
  // ===========================================================================
  server.tool(
    'crowdstrike_get_host_groups',
    `Get detailed information for specific host groups by their IDs.

Args:
  - ids: Array of host group IDs to retrieve

Returns:
  Detailed host group information including name, type, description, and assignment rules.`,
    {
      ids: z.array(z.string()).min(1).describe('Host group IDs to retrieve'),
    },
    async ({ ids }) => {
      try {
        const groups = await client.getHostGroups(ids);
        return formatResponse(groups, 'json', 'host_groups');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Host Group
  // ===========================================================================
  server.tool(
    'crowdstrike_create_host_group',
    `Create a new host group in CrowdStrike Falcon.

Args:
  - name: Name of the host group
  - group_type: Type of group (static, dynamic, staticByID)
    - static: Manually assigned hosts
    - dynamic: Hosts matching an FQL assignment rule
    - staticByID: Specific hosts by device ID
  - description: Description of the group (optional)
  - assignment_rule: FQL rule for dynamic groups (e.g., "platform_name:'Windows'+hostname:'prod-*'")

Returns:
  The created host group.`,
    {
      name: z.string().describe('Group name'),
      group_type: z.enum(['static', 'dynamic', 'staticByID']).describe('Group type'),
      description: z.string().optional().describe('Description'),
      assignment_rule: z.string().optional().describe('FQL assignment rule for dynamic groups'),
    },
    async ({ name, group_type, description, assignment_rule }) => {
      try {
        const group = await client.createHostGroup({
          name,
          group_type,
          description,
          assignment_rule,
        });
        return formatResponse(group, 'json', 'host_group');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Update Host Group
  // ===========================================================================
  server.tool(
    'crowdstrike_update_host_group',
    `Update an existing host group.

Args:
  - id: ID of the host group to update
  - name: New name (optional)
  - description: New description (optional)
  - assignment_rule: New FQL assignment rule for dynamic groups (optional)

Returns:
  The updated host group.`,
    {
      id: z.string().describe('Host group ID'),
      name: z.string().optional().describe('New name'),
      description: z.string().optional().describe('New description'),
      assignment_rule: z.string().optional().describe('New assignment rule'),
    },
    async ({ id, name, description, assignment_rule }) => {
      try {
        const group = await client.updateHostGroup(id, {
          name,
          description,
          assignment_rule,
        });
        return formatResponse(group, 'json', 'host_group');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Delete Host Groups
  // ===========================================================================
  server.tool(
    'crowdstrike_delete_host_groups',
    `Delete one or more host groups.

Args:
  - ids: Array of host group IDs to delete

Returns:
  Confirmation of deletion.`,
    {
      ids: z.array(z.string()).min(1).describe('Host group IDs to delete'),
    },
    async ({ ids }) => {
      try {
        const result = await client.deleteHostGroups(ids);
        return formatResponse(result, 'json', 'delete');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Add Hosts to Group
  // ===========================================================================
  server.tool(
    'crowdstrike_add_hosts_to_group',
    `Add hosts to a static host group.

Note: Only works with static or staticByID group types.

Args:
  - group_id: Host group ID
  - host_ids: Array of device IDs to add

Returns:
  Confirmation of action.`,
    {
      group_id: z.string().describe('Host group ID'),
      host_ids: z.array(z.string()).min(1).describe('Device IDs to add'),
    },
    async ({ group_id, host_ids }) => {
      try {
        const result = await client.addHostsToGroup(group_id, host_ids);
        return formatResponse(result, 'json', 'add_hosts');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Remove Hosts from Group
  // ===========================================================================
  server.tool(
    'crowdstrike_remove_hosts_from_group',
    `Remove hosts from a static host group.

Note: Only works with static or staticByID group types.

Args:
  - group_id: Host group ID
  - host_ids: Array of device IDs to remove

Returns:
  Confirmation of action.`,
    {
      group_id: z.string().describe('Host group ID'),
      host_ids: z.array(z.string()).min(1).describe('Device IDs to remove'),
    },
    async ({ group_id, host_ids }) => {
      try {
        const result = await client.removeHostsFromGroup(group_id, host_ids);
        return formatResponse(result, 'json', 'remove_hosts');
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
