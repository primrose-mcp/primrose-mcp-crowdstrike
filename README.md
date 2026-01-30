# CrowdStrike Falcon MCP Server

[![Primrose MCP](https://img.shields.io/badge/Primrose-MCP-blue)](https://primrose.dev/mcp/crowdstrike)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Model Context Protocol (MCP) server for CrowdStrike Falcon. Manage endpoint security, detect threats, investigate incidents, and respond to security events through a standardized interface.

## Features

- **Host Management** - Monitor and manage protected endpoints
- **Detection Handling** - Access and manage threat detections
- **Incident Response** - Investigate and respond to security incidents
- **Alert Management** - Monitor and triage security alerts
- **IOC Management** - Manage Indicators of Compromise
- **Vulnerability Tracking** - Monitor endpoint vulnerabilities
- **Host Groups** - Organize hosts into logical groups
- **Policy Management** - Configure and apply security policies
- **Real-Time Response** - Execute RTR commands on endpoints

## Quick Start

The recommended way to use this MCP server is through the [Primrose SDK](https://www.npmjs.com/package/primrose-mcp):

```bash
npm install primrose-mcp
```

```typescript
import { PrimroseClient } from 'primrose-mcp';

const client = new PrimroseClient({
  service: 'crowdstrike',
  headers: {
    'X-CrowdStrike-Client-ID': 'your-client-id',
    'X-CrowdStrike-Client-Secret': 'your-client-secret'
  }
});

// List hosts
const hosts = await client.call('crowdstrike_list_hosts', {});
```

## Manual Installation

If you prefer to run the MCP server directly:

```bash
# Clone the repository
git clone https://github.com/primrose-ai/primrose-mcp-crowdstrike.git
cd primrose-mcp-crowdstrike

# Install dependencies
npm install

# Build the project
npm run build

# Start the server
npm start
```

## Configuration

### Required Headers

| Header | Description |
|--------|-------------|
| `X-CrowdStrike-Client-ID` | OAuth2 Client ID |
| `X-CrowdStrike-Client-Secret` | OAuth2 Client Secret |

### Optional Headers

| Header | Description |
|--------|-------------|
| `X-CrowdStrike-Base-URL` | Override default API base URL (default: api.crowdstrike.com) |

### Regional Base URLs

- **US-1**: `api.crowdstrike.com` (default)
- **US-2**: `api.us-2.crowdstrike.com`
- **EU-1**: `api.eu-1.crowdstrike.com`
- **US-GOV-1**: `api.laggar.gcw.crowdstrike.com`

### Getting Your API Credentials

1. Log in to the [Falcon Console](https://falcon.crowdstrike.com)
2. Navigate to Support > API Clients and Keys
3. Click "Add new API client"
4. Configure the required API scopes
5. Copy the Client ID and Client Secret

## Available Tools

### Host Tools
- `crowdstrike_list_hosts` - List all hosts
- `crowdstrike_get_host` - Get host details
- `crowdstrike_search_hosts` - Search hosts with FQL
- `crowdstrike_contain_host` - Network contain a host
- `crowdstrike_lift_containment` - Lift network containment

### Detection Tools
- `crowdstrike_list_detections` - List threat detections
- `crowdstrike_get_detection` - Get detection details
- `crowdstrike_update_detection` - Update detection status

### Incident Tools
- `crowdstrike_list_incidents` - List security incidents
- `crowdstrike_get_incident` - Get incident details
- `crowdstrike_update_incident` - Update incident status

### Alert Tools
- `crowdstrike_list_alerts` - List security alerts
- `crowdstrike_get_alert` - Get alert details
- `crowdstrike_update_alert` - Update alert status

### IOC Tools
- `crowdstrike_list_iocs` - List custom IOCs
- `crowdstrike_create_ioc` - Create a custom IOC
- `crowdstrike_update_ioc` - Update an IOC
- `crowdstrike_delete_ioc` - Delete an IOC

### Vulnerability Tools
- `crowdstrike_list_vulnerabilities` - List endpoint vulnerabilities
- `crowdstrike_get_vulnerability` - Get vulnerability details

### Host Group Tools
- `crowdstrike_list_host_groups` - List host groups
- `crowdstrike_create_host_group` - Create a host group
- `crowdstrike_update_host_group` - Update a host group
- `crowdstrike_add_hosts_to_group` - Add hosts to a group

### Policy Tools
- `crowdstrike_list_policies` - List prevention policies
- `crowdstrike_get_policy` - Get policy details
- `crowdstrike_update_policy` - Update policy settings

### Real-Time Response (RTR) Tools
- `crowdstrike_init_rtr_session` - Start an RTR session
- `crowdstrike_execute_rtr_command` - Execute RTR command
- `crowdstrike_get_rtr_result` - Get RTR command result
- `crowdstrike_delete_rtr_session` - End RTR session

## Development

```bash
# Run in development mode with hot reload
npm run dev

# Run tests
npm test

# Lint code
npm run lint

# Type check
npm run typecheck
```

## Related Resources

- [Primrose SDK Documentation](https://primrose.dev/docs)
- [CrowdStrike Falcon API Documentation](https://falcon.crowdstrike.com/documentation/page/a2a7fc0e/crowdstrike-oauth2-based-apis)
- [Model Context Protocol](https://modelcontextprotocol.io)
