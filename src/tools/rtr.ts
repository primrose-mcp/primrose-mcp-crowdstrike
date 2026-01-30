/**
 * Real-Time Response Tools
 *
 * MCP tools for CrowdStrike Real-Time Response (RTR) capabilities.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { CrowdStrikeClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

/**
 * Register all Real-Time Response tools
 */
export function registerRTRTools(server: McpServer, client: CrowdStrikeClient): void {
  // ===========================================================================
  // Initialize RTR Session
  // ===========================================================================
  server.tool(
    'crowdstrike_init_rtr_session',
    `Initialize a Real-Time Response session with a host.

RTR allows you to execute commands directly on endpoints for investigation and remediation.

Args:
  - device_id: The device ID to connect to
  - queue_offline: If true, queue commands for offline hosts (default: false)

Returns:
  Session information including session_id needed for subsequent commands.`,
    {
      device_id: z.string().describe('Device ID to connect to'),
      queue_offline: z.boolean().optional().default(false).describe('Queue for offline hosts'),
    },
    async ({ device_id, queue_offline }) => {
      try {
        const session = await client.initRTRSession(device_id, queue_offline);
        return formatResponse(session, 'json', 'rtr_session');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Execute RTR Read-Only Command
  // ===========================================================================
  server.tool(
    'crowdstrike_rtr_command',
    `Execute a read-only RTR command on an active session.

Read-only commands allow investigation without modifying the endpoint.

Available base commands include:
  - cat: Read file contents
  - cd: Change directory
  - env: Display environment variables
  - eventlog: Inspect event logs (Windows)
  - filehash: Calculate file hash
  - getsid: Get SID info (Windows)
  - history: Command history (Linux/Mac)
  - ifconfig: Network configuration (Linux/Mac)
  - ipconfig: Network configuration (Windows)
  - ls: List directory
  - mount: View mounts (Linux/Mac)
  - netstat: Network connections
  - ps: List processes
  - reg query: Query registry (Windows)
  - users: List logged in users

Args:
  - session_id: Active RTR session ID
  - base_command: The RTR base command (e.g., "ls", "ps", "netstat")
  - command_string: Full command with arguments (e.g., "ls -la /tmp")

Returns:
  Command output including stdout and stderr.`,
    {
      session_id: z.string().describe('RTR session ID'),
      base_command: z.string().describe('Base RTR command'),
      command_string: z.string().describe('Full command with arguments'),
    },
    async ({ session_id, base_command, command_string }) => {
      try {
        const result = await client.executeRTRCommand(session_id, base_command, command_string);
        return formatResponse(result, 'json', 'rtr_result');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Execute RTR Active Responder Command
  // ===========================================================================
  server.tool(
    'crowdstrike_rtr_active_responder_command',
    `Execute an active responder RTR command that can modify the endpoint.

WARNING: These commands can make changes to the endpoint. Use with caution.

Active responder commands include:
  - cp: Copy files
  - encrypt: Encrypt files
  - kill: Terminate processes
  - map: Map network drive (Windows)
  - memdump: Memory dump
  - mkdir: Create directory
  - mv: Move/rename files
  - reg set/delete: Modify registry (Windows)
  - restart: Restart system
  - rm: Delete files
  - runscript: Execute a script
  - shutdown: Shutdown system
  - unmap: Unmap network drive (Windows)
  - update history/install/list: Manage updates (Linux)
  - xmemdump: Extended memory dump
  - zip: Compress files

Args:
  - session_id: Active RTR session ID
  - base_command: The RTR base command (e.g., "kill", "rm", "runscript")
  - command_string: Full command with arguments

Returns:
  Command output including stdout and stderr.`,
    {
      session_id: z.string().describe('RTR session ID'),
      base_command: z.string().describe('Base RTR command'),
      command_string: z.string().describe('Full command with arguments'),
    },
    async ({ session_id, base_command, command_string }) => {
      try {
        const result = await client.executeRTRActiveResponderCommand(
          session_id,
          base_command,
          command_string
        );
        return formatResponse(result, 'json', 'rtr_result');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Delete RTR Session
  // ===========================================================================
  server.tool(
    'crowdstrike_delete_rtr_session',
    `Close and delete an RTR session.

Sessions should be closed when investigation is complete to free resources.

Args:
  - session_id: RTR session ID to delete

Returns:
  Confirmation of session deletion.`,
    {
      session_id: z.string().describe('RTR session ID to delete'),
    },
    async ({ session_id }) => {
      try {
        const result = await client.deleteRTRSession(session_id);
        return formatResponse(result, 'json', 'delete');
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
