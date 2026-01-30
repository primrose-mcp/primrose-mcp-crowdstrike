/**
 * CrowdStrike Falcon API Client
 *
 * This file handles all HTTP communication with the CrowdStrike Falcon API.
 *
 * MULTI-TENANT: This client receives credentials per-request via TenantCredentials,
 * allowing a single server to serve multiple tenants with different API keys.
 */

import type {
  Alert,
  CrowdStrikeResponse,
  Detection,
  Host,
  HostGroup,
  HostGroupCreateInput,
  Incident,
  IncidentBehavior,
  IOC,
  IOCCreateInput,
  OAuth2TokenResponse,
  Policy,
  RTRCommandResult,
  RTRSession,
  Vulnerability,
} from './types/crowdstrike.js';
import type { TenantCredentials } from './types/env.js';
import { AuthenticationError, CrowdStrikeApiError, RateLimitError } from './utils/errors.js';

// =============================================================================
// Configuration
// =============================================================================

const DEFAULT_BASE_URL = 'https://api.crowdstrike.com';

// =============================================================================
// CrowdStrike Client Interface
// =============================================================================

export interface CrowdStrikeClient {
  // Connection
  testConnection(): Promise<{ connected: boolean; message: string }>;

  // Hosts
  queryHosts(params?: QueryParams): Promise<string[]>;
  getHosts(ids: string[]): Promise<Host[]>;
  containHost(ids: string[]): Promise<{ success: boolean; message: string }>;
  liftContainment(ids: string[]): Promise<{ success: boolean; message: string }>;
  hideHost(ids: string[]): Promise<{ success: boolean; message: string }>;
  unhideHost(ids: string[]): Promise<{ success: boolean; message: string }>;

  // Detections
  queryDetections(params?: QueryParams): Promise<string[]>;
  getDetections(ids: string[]): Promise<Detection[]>;
  updateDetectionStatus(
    ids: string[],
    status: string,
    assignedToUuid?: string,
    comment?: string
  ): Promise<{ success: boolean; message: string }>;

  // Incidents
  queryIncidents(params?: QueryParams): Promise<string[]>;
  getIncidents(ids: string[]): Promise<Incident[]>;
  updateIncident(
    ids: string[],
    action: string,
    value?: string
  ): Promise<{ success: boolean; message: string }>;
  getBehaviors(ids: string[]): Promise<IncidentBehavior[]>;

  // Alerts
  queryAlerts(params?: QueryParams): Promise<string[]>;
  getAlerts(ids: string[]): Promise<Alert[]>;
  updateAlerts(
    ids: string[],
    status?: string,
    assignedTo?: string,
    comment?: string
  ): Promise<{ success: boolean; message: string }>;

  // IOCs
  queryIOCs(params?: QueryParams): Promise<string[]>;
  getIOCs(ids: string[]): Promise<IOC[]>;
  createIOC(input: IOCCreateInput): Promise<IOC>;
  updateIOC(id: string, input: Partial<IOCCreateInput>): Promise<IOC>;
  deleteIOCs(ids: string[]): Promise<{ success: boolean; message: string }>;

  // Spotlight Vulnerabilities
  queryVulnerabilities(filter: string, params?: QueryParams): Promise<string[]>;
  getVulnerabilities(ids: string[]): Promise<Vulnerability[]>;

  // Host Groups
  queryHostGroups(params?: QueryParams): Promise<string[]>;
  getHostGroups(ids: string[]): Promise<HostGroup[]>;
  createHostGroup(input: HostGroupCreateInput): Promise<HostGroup>;
  updateHostGroup(
    id: string,
    input: Partial<HostGroupCreateInput>
  ): Promise<HostGroup>;
  deleteHostGroups(ids: string[]): Promise<{ success: boolean; message: string }>;
  addHostsToGroup(groupId: string, hostIds: string[]): Promise<{ success: boolean; message: string }>;
  removeHostsFromGroup(groupId: string, hostIds: string[]): Promise<{ success: boolean; message: string }>;

  // Prevention Policies
  queryPreventionPolicies(params?: QueryParams): Promise<string[]>;
  getPreventionPolicies(ids: string[]): Promise<Policy[]>;

  // Device Control Policies
  queryDeviceControlPolicies(params?: QueryParams): Promise<string[]>;
  getDeviceControlPolicies(ids: string[]): Promise<Policy[]>;

  // Sensor Update Policies
  querySensorUpdatePolicies(params?: QueryParams): Promise<string[]>;
  getSensorUpdatePolicies(ids: string[]): Promise<Policy[]>;

  // Real-Time Response
  initRTRSession(deviceId: string, queueOffline?: boolean): Promise<RTRSession>;
  executeRTRCommand(
    sessionId: string,
    baseCommand: string,
    commandString: string
  ): Promise<RTRCommandResult>;
  executeRTRActiveResponderCommand(
    sessionId: string,
    baseCommand: string,
    commandString: string
  ): Promise<RTRCommandResult>;
  deleteRTRSession(sessionId: string): Promise<{ success: boolean; message: string }>;
}

export interface QueryParams {
  filter?: string;
  limit?: number;
  offset?: number;
  sort?: string;
  after?: string;
}

// =============================================================================
// CrowdStrike Client Implementation
// =============================================================================

class CrowdStrikeClientImpl implements CrowdStrikeClient {
  private credentials: TenantCredentials;
  private baseUrl: string;
  private accessToken: string | null = null;
  private tokenExpiry: number = 0;

  constructor(credentials: TenantCredentials) {
    this.credentials = credentials;
    this.baseUrl = credentials.baseUrl || DEFAULT_BASE_URL;
  }

  // ===========================================================================
  // OAuth2 Authentication
  // ===========================================================================

  private async getAccessToken(): Promise<string> {
    // Return cached token if still valid (with 60-second buffer)
    if (this.accessToken && Date.now() < this.tokenExpiry - 60000) {
      return this.accessToken;
    }

    const response = await fetch(`${this.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `client_id=${encodeURIComponent(this.credentials.clientId)}&client_secret=${encodeURIComponent(this.credentials.clientSecret)}`,
    });

    if (!response.ok) {
      throw new AuthenticationError(
        `OAuth2 authentication failed: ${response.status} ${response.statusText}`
      );
    }

    const data = (await response.json()) as OAuth2TokenResponse;
    this.accessToken = data.access_token;
    this.tokenExpiry = Date.now() + data.expires_in * 1000;

    return this.accessToken;
  }

  private async getAuthHeaders(): Promise<Record<string, string>> {
    const token = await this.getAccessToken();
    return {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    };
  }

  // ===========================================================================
  // HTTP Request Helper
  // ===========================================================================

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const headers = await this.getAuthHeaders();

    const response = await fetch(url, {
      ...options,
      headers: {
        ...headers,
        ...(options.headers || {}),
      },
    });

    // Handle rate limiting
    if (response.status === 429) {
      const retryAfter = response.headers.get('X-RateLimit-RetryAfter');
      throw new RateLimitError(
        'Rate limit exceeded',
        retryAfter ? parseInt(retryAfter, 10) : 60
      );
    }

    // Handle authentication errors
    if (response.status === 401 || response.status === 403) {
      // Clear cached token and try once more
      this.accessToken = null;
      throw new AuthenticationError(
        'Authentication failed. Check your API credentials.'
      );
    }

    // Handle other errors
    if (!response.ok) {
      const errorBody = await response.text();
      let message = `API error: ${response.status}`;
      try {
        const errorJson = JSON.parse(errorBody);
        if (errorJson.errors?.length) {
          message = errorJson.errors.map((e: { message: string }) => e.message).join('; ');
        } else if (errorJson.message) {
          message = errorJson.message;
        }
      } catch {
        // Use default message
      }
      throw new CrowdStrikeApiError(message, response.status);
    }

    // Handle 204 No Content
    if (response.status === 204) {
      return undefined as T;
    }

    return response.json() as Promise<T>;
  }

  // ===========================================================================
  // Connection
  // ===========================================================================

  async testConnection(): Promise<{ connected: boolean; message: string }> {
    try {
      await this.getAccessToken();
      // Try a simple query to verify permissions
      await this.request<CrowdStrikeResponse<string>>(
        '/devices/queries/devices/v1?limit=1'
      );
      return { connected: true, message: 'Successfully connected to CrowdStrike Falcon API' };
    } catch (error) {
      return {
        connected: false,
        message: error instanceof Error ? error.message : 'Connection failed',
      };
    }
  }

  // ===========================================================================
  // Hosts
  // ===========================================================================

  async queryHosts(params?: QueryParams): Promise<string[]> {
    const queryParams = new URLSearchParams();
    if (params?.filter) queryParams.set('filter', params.filter);
    if (params?.limit) queryParams.set('limit', String(params.limit));
    if (params?.offset) queryParams.set('offset', String(params.offset));
    if (params?.sort) queryParams.set('sort', params.sort);

    const response = await this.request<CrowdStrikeResponse<string>>(
      `/devices/queries/devices/v1?${queryParams}`
    );
    return response.resources || [];
  }

  async getHosts(ids: string[]): Promise<Host[]> {
    if (ids.length === 0) return [];

    const response = await this.request<CrowdStrikeResponse<Host>>(
      '/devices/entities/devices/v2',
      {
        method: 'POST',
        body: JSON.stringify({ ids }),
      }
    );
    return response.resources || [];
  }

  async containHost(ids: string[]): Promise<{ success: boolean; message: string }> {
    await this.request(
      '/devices/entities/devices-actions/v2?action_name=contain',
      {
        method: 'POST',
        body: JSON.stringify({ ids }),
      }
    );
    return { success: true, message: `Containment initiated for ${ids.length} host(s)` };
  }

  async liftContainment(ids: string[]): Promise<{ success: boolean; message: string }> {
    await this.request(
      '/devices/entities/devices-actions/v2?action_name=lift_containment',
      {
        method: 'POST',
        body: JSON.stringify({ ids }),
      }
    );
    return { success: true, message: `Containment lifted for ${ids.length} host(s)` };
  }

  async hideHost(ids: string[]): Promise<{ success: boolean; message: string }> {
    await this.request(
      '/devices/entities/devices-actions/v2?action_name=hide_host',
      {
        method: 'POST',
        body: JSON.stringify({ ids }),
      }
    );
    return { success: true, message: `Hidden ${ids.length} host(s)` };
  }

  async unhideHost(ids: string[]): Promise<{ success: boolean; message: string }> {
    await this.request(
      '/devices/entities/devices-actions/v2?action_name=unhide_host',
      {
        method: 'POST',
        body: JSON.stringify({ ids }),
      }
    );
    return { success: true, message: `Unhidden ${ids.length} host(s)` };
  }

  // ===========================================================================
  // Detections
  // ===========================================================================

  async queryDetections(params?: QueryParams): Promise<string[]> {
    const queryParams = new URLSearchParams();
    if (params?.filter) queryParams.set('filter', params.filter);
    if (params?.limit) queryParams.set('limit', String(params.limit));
    if (params?.offset) queryParams.set('offset', String(params.offset));
    if (params?.sort) queryParams.set('sort', params.sort);

    const response = await this.request<CrowdStrikeResponse<string>>(
      `/detects/queries/detects/v1?${queryParams}`
    );
    return response.resources || [];
  }

  async getDetections(ids: string[]): Promise<Detection[]> {
    if (ids.length === 0) return [];

    const response = await this.request<CrowdStrikeResponse<Detection>>(
      '/detects/entities/summaries/GET/v1',
      {
        method: 'POST',
        body: JSON.stringify({ ids }),
      }
    );
    return response.resources || [];
  }

  async updateDetectionStatus(
    ids: string[],
    status: string,
    assignedToUuid?: string,
    comment?: string
  ): Promise<{ success: boolean; message: string }> {
    const body: Record<string, unknown> = { ids, status };
    if (assignedToUuid) body.assigned_to_uuid = assignedToUuid;
    if (comment) body.comment = comment;

    await this.request('/detects/entities/detects/v2', {
      method: 'PATCH',
      body: JSON.stringify(body),
    });
    return { success: true, message: `Updated status to '${status}' for ${ids.length} detection(s)` };
  }

  // ===========================================================================
  // Incidents
  // ===========================================================================

  async queryIncidents(params?: QueryParams): Promise<string[]> {
    const queryParams = new URLSearchParams();
    if (params?.filter) queryParams.set('filter', params.filter);
    if (params?.limit) queryParams.set('limit', String(params.limit));
    if (params?.offset) queryParams.set('offset', String(params.offset));
    if (params?.sort) queryParams.set('sort', params.sort);

    const response = await this.request<CrowdStrikeResponse<string>>(
      `/incidents/queries/incidents/v1?${queryParams}`
    );
    return response.resources || [];
  }

  async getIncidents(ids: string[]): Promise<Incident[]> {
    if (ids.length === 0) return [];

    const response = await this.request<CrowdStrikeResponse<Incident>>(
      '/incidents/entities/incidents/GET/v1',
      {
        method: 'POST',
        body: JSON.stringify({ ids }),
      }
    );
    return response.resources || [];
  }

  async updateIncident(
    ids: string[],
    action: string,
    value?: string
  ): Promise<{ success: boolean; message: string }> {
    await this.request('/incidents/entities/incident-actions/v1', {
      method: 'POST',
      body: JSON.stringify({
        ids,
        action_parameters: [{ name: action, value: value || '' }],
      }),
    });
    return { success: true, message: `Action '${action}' applied to ${ids.length} incident(s)` };
  }

  async getBehaviors(ids: string[]): Promise<IncidentBehavior[]> {
    if (ids.length === 0) return [];

    const response = await this.request<CrowdStrikeResponse<IncidentBehavior>>(
      '/incidents/entities/behaviors/GET/v1',
      {
        method: 'POST',
        body: JSON.stringify({ ids }),
      }
    );
    return response.resources || [];
  }

  // ===========================================================================
  // Alerts
  // ===========================================================================

  async queryAlerts(params?: QueryParams): Promise<string[]> {
    const queryParams = new URLSearchParams();
    if (params?.filter) queryParams.set('filter', params.filter);
    if (params?.limit) queryParams.set('limit', String(params.limit));
    if (params?.offset) queryParams.set('offset', String(params.offset));
    if (params?.sort) queryParams.set('sort', params.sort);

    const response = await this.request<CrowdStrikeResponse<string>>(
      `/alerts/queries/alerts/v1?${queryParams}`
    );
    return response.resources || [];
  }

  async getAlerts(ids: string[]): Promise<Alert[]> {
    if (ids.length === 0) return [];

    const response = await this.request<CrowdStrikeResponse<Alert>>(
      '/alerts/entities/alerts/v1',
      {
        method: 'POST',
        body: JSON.stringify({ ids }),
      }
    );
    return response.resources || [];
  }

  async updateAlerts(
    ids: string[],
    status?: string,
    assignedTo?: string,
    comment?: string
  ): Promise<{ success: boolean; message: string }> {
    const body: Record<string, unknown> = { ids };
    if (status) body.update_status = status;
    if (assignedTo) body.assign_to = assignedTo;
    if (comment) body.add_comment = comment;

    await this.request('/alerts/entities/alerts/v2', {
      method: 'PATCH',
      body: JSON.stringify(body),
    });
    return { success: true, message: `Updated ${ids.length} alert(s)` };
  }

  // ===========================================================================
  // IOCs
  // ===========================================================================

  async queryIOCs(params?: QueryParams): Promise<string[]> {
    const queryParams = new URLSearchParams();
    if (params?.filter) queryParams.set('filter', params.filter);
    if (params?.limit) queryParams.set('limit', String(params.limit));
    if (params?.offset) queryParams.set('offset', String(params.offset));
    if (params?.sort) queryParams.set('sort', params.sort);
    if (params?.after) queryParams.set('after', params.after);

    const response = await this.request<CrowdStrikeResponse<string>>(
      `/iocs/queries/indicators/v1?${queryParams}`
    );
    return response.resources || [];
  }

  async getIOCs(ids: string[]): Promise<IOC[]> {
    if (ids.length === 0) return [];

    const queryParams = new URLSearchParams();
    ids.forEach((id) => queryParams.append('ids', id));

    const response = await this.request<CrowdStrikeResponse<IOC>>(
      `/iocs/entities/indicators/v1?${queryParams}`
    );
    return response.resources || [];
  }

  async createIOC(input: IOCCreateInput): Promise<IOC> {
    const response = await this.request<CrowdStrikeResponse<IOC>>(
      '/iocs/entities/indicators/v1',
      {
        method: 'POST',
        body: JSON.stringify({
          indicators: [input],
        }),
      }
    );
    return response.resources[0];
  }

  async updateIOC(id: string, input: Partial<IOCCreateInput>): Promise<IOC> {
    const response = await this.request<CrowdStrikeResponse<IOC>>(
      '/iocs/entities/indicators/v1',
      {
        method: 'PATCH',
        body: JSON.stringify({
          indicators: [{ id, ...input }],
        }),
      }
    );
    return response.resources[0];
  }

  async deleteIOCs(ids: string[]): Promise<{ success: boolean; message: string }> {
    const queryParams = new URLSearchParams();
    ids.forEach((id) => queryParams.append('ids', id));

    await this.request(`/iocs/entities/indicators/v1?${queryParams}`, {
      method: 'DELETE',
    });
    return { success: true, message: `Deleted ${ids.length} IOC(s)` };
  }

  // ===========================================================================
  // Spotlight Vulnerabilities
  // ===========================================================================

  async queryVulnerabilities(filter: string, params?: QueryParams): Promise<string[]> {
    const queryParams = new URLSearchParams();
    queryParams.set('filter', filter);
    if (params?.limit) queryParams.set('limit', String(params.limit));
    if (params?.after) queryParams.set('after', params.after);
    if (params?.sort) queryParams.set('sort', params.sort);

    const response = await this.request<CrowdStrikeResponse<string>>(
      `/spotlight/queries/vulnerabilities/v1?${queryParams}`
    );
    return response.resources || [];
  }

  async getVulnerabilities(ids: string[]): Promise<Vulnerability[]> {
    if (ids.length === 0) return [];

    const queryParams = new URLSearchParams();
    ids.forEach((id) => queryParams.append('ids', id));

    const response = await this.request<CrowdStrikeResponse<Vulnerability>>(
      `/spotlight/entities/vulnerabilities/v2?${queryParams}`
    );
    return response.resources || [];
  }

  // ===========================================================================
  // Host Groups
  // ===========================================================================

  async queryHostGroups(params?: QueryParams): Promise<string[]> {
    const queryParams = new URLSearchParams();
    if (params?.filter) queryParams.set('filter', params.filter);
    if (params?.limit) queryParams.set('limit', String(params.limit));
    if (params?.offset) queryParams.set('offset', String(params.offset));
    if (params?.sort) queryParams.set('sort', params.sort);

    const response = await this.request<CrowdStrikeResponse<string>>(
      `/devices/queries/host-groups/v1?${queryParams}`
    );
    return response.resources || [];
  }

  async getHostGroups(ids: string[]): Promise<HostGroup[]> {
    if (ids.length === 0) return [];

    const queryParams = new URLSearchParams();
    ids.forEach((id) => queryParams.append('ids', id));

    const response = await this.request<CrowdStrikeResponse<HostGroup>>(
      `/devices/entities/host-groups/v1?${queryParams}`
    );
    return response.resources || [];
  }

  async createHostGroup(input: HostGroupCreateInput): Promise<HostGroup> {
    const response = await this.request<CrowdStrikeResponse<HostGroup>>(
      '/devices/entities/host-groups/v1',
      {
        method: 'POST',
        body: JSON.stringify({
          resources: [input],
        }),
      }
    );
    return response.resources[0];
  }

  async updateHostGroup(
    id: string,
    input: Partial<HostGroupCreateInput>
  ): Promise<HostGroup> {
    const response = await this.request<CrowdStrikeResponse<HostGroup>>(
      '/devices/entities/host-groups/v1',
      {
        method: 'PATCH',
        body: JSON.stringify({
          resources: [{ id, ...input }],
        }),
      }
    );
    return response.resources[0];
  }

  async deleteHostGroups(ids: string[]): Promise<{ success: boolean; message: string }> {
    const queryParams = new URLSearchParams();
    ids.forEach((id) => queryParams.append('ids', id));

    await this.request(`/devices/entities/host-groups/v1?${queryParams}`, {
      method: 'DELETE',
    });
    return { success: true, message: `Deleted ${ids.length} host group(s)` };
  }

  async addHostsToGroup(
    groupId: string,
    hostIds: string[]
  ): Promise<{ success: boolean; message: string }> {
    await this.request(
      `/devices/entities/host-group-actions/v1?action_name=add-hosts`,
      {
        method: 'POST',
        body: JSON.stringify({
          ids: [groupId],
          action_parameters: [{ name: 'filter', value: hostIds.map((id) => `device_id:'${id}'`).join(',') }],
        }),
      }
    );
    return { success: true, message: `Added ${hostIds.length} host(s) to group` };
  }

  async removeHostsFromGroup(
    groupId: string,
    hostIds: string[]
  ): Promise<{ success: boolean; message: string }> {
    await this.request(
      `/devices/entities/host-group-actions/v1?action_name=remove-hosts`,
      {
        method: 'POST',
        body: JSON.stringify({
          ids: [groupId],
          action_parameters: [{ name: 'filter', value: hostIds.map((id) => `device_id:'${id}'`).join(',') }],
        }),
      }
    );
    return { success: true, message: `Removed ${hostIds.length} host(s) from group` };
  }

  // ===========================================================================
  // Prevention Policies
  // ===========================================================================

  async queryPreventionPolicies(params?: QueryParams): Promise<string[]> {
    const queryParams = new URLSearchParams();
    if (params?.filter) queryParams.set('filter', params.filter);
    if (params?.limit) queryParams.set('limit', String(params.limit));
    if (params?.offset) queryParams.set('offset', String(params.offset));
    if (params?.sort) queryParams.set('sort', params.sort);

    const response = await this.request<CrowdStrikeResponse<string>>(
      `/policy/queries/prevention/v1?${queryParams}`
    );
    return response.resources || [];
  }

  async getPreventionPolicies(ids: string[]): Promise<Policy[]> {
    if (ids.length === 0) return [];

    const queryParams = new URLSearchParams();
    ids.forEach((id) => queryParams.append('ids', id));

    const response = await this.request<CrowdStrikeResponse<Policy>>(
      `/policy/entities/prevention/v1?${queryParams}`
    );
    return response.resources || [];
  }

  // ===========================================================================
  // Device Control Policies
  // ===========================================================================

  async queryDeviceControlPolicies(params?: QueryParams): Promise<string[]> {
    const queryParams = new URLSearchParams();
    if (params?.filter) queryParams.set('filter', params.filter);
    if (params?.limit) queryParams.set('limit', String(params.limit));
    if (params?.offset) queryParams.set('offset', String(params.offset));
    if (params?.sort) queryParams.set('sort', params.sort);

    const response = await this.request<CrowdStrikeResponse<string>>(
      `/policy/queries/device-control/v1?${queryParams}`
    );
    return response.resources || [];
  }

  async getDeviceControlPolicies(ids: string[]): Promise<Policy[]> {
    if (ids.length === 0) return [];

    const queryParams = new URLSearchParams();
    ids.forEach((id) => queryParams.append('ids', id));

    const response = await this.request<CrowdStrikeResponse<Policy>>(
      `/policy/entities/device-control/v1?${queryParams}`
    );
    return response.resources || [];
  }

  // ===========================================================================
  // Sensor Update Policies
  // ===========================================================================

  async querySensorUpdatePolicies(params?: QueryParams): Promise<string[]> {
    const queryParams = new URLSearchParams();
    if (params?.filter) queryParams.set('filter', params.filter);
    if (params?.limit) queryParams.set('limit', String(params.limit));
    if (params?.offset) queryParams.set('offset', String(params.offset));
    if (params?.sort) queryParams.set('sort', params.sort);

    const response = await this.request<CrowdStrikeResponse<string>>(
      `/policy/queries/sensor-update/v1?${queryParams}`
    );
    return response.resources || [];
  }

  async getSensorUpdatePolicies(ids: string[]): Promise<Policy[]> {
    if (ids.length === 0) return [];

    const queryParams = new URLSearchParams();
    ids.forEach((id) => queryParams.append('ids', id));

    const response = await this.request<CrowdStrikeResponse<Policy>>(
      `/policy/entities/sensor-update/v2?${queryParams}`
    );
    return response.resources || [];
  }

  // ===========================================================================
  // Real-Time Response
  // ===========================================================================

  async initRTRSession(
    deviceId: string,
    queueOffline = false
  ): Promise<RTRSession> {
    const response = await this.request<CrowdStrikeResponse<RTRSession>>(
      '/real-time-response/entities/sessions/v1',
      {
        method: 'POST',
        body: JSON.stringify({
          device_id: deviceId,
          queue_offline: queueOffline,
        }),
      }
    );
    return response.resources[0];
  }

  async executeRTRCommand(
    sessionId: string,
    baseCommand: string,
    commandString: string
  ): Promise<RTRCommandResult> {
    const response = await this.request<CrowdStrikeResponse<RTRCommandResult>>(
      '/real-time-response/entities/command/v1',
      {
        method: 'POST',
        body: JSON.stringify({
          session_id: sessionId,
          base_command: baseCommand,
          command_string: commandString,
        }),
      }
    );
    return response.resources[0];
  }

  async executeRTRActiveResponderCommand(
    sessionId: string,
    baseCommand: string,
    commandString: string
  ): Promise<RTRCommandResult> {
    const response = await this.request<CrowdStrikeResponse<RTRCommandResult>>(
      '/real-time-response/entities/active-responder-command/v1',
      {
        method: 'POST',
        body: JSON.stringify({
          session_id: sessionId,
          base_command: baseCommand,
          command_string: commandString,
        }),
      }
    );
    return response.resources[0];
  }

  async deleteRTRSession(
    sessionId: string
  ): Promise<{ success: boolean; message: string }> {
    await this.request(
      `/real-time-response/entities/sessions/v1?session_id=${encodeURIComponent(sessionId)}`,
      {
        method: 'DELETE',
      }
    );
    return { success: true, message: 'Session deleted' };
  }
}

// =============================================================================
// Factory Function
// =============================================================================

/**
 * Create a CrowdStrike client instance with tenant-specific credentials.
 *
 * MULTI-TENANT: Each request provides its own credentials via headers,
 * allowing a single server deployment to serve multiple tenants.
 *
 * @param credentials - Tenant credentials parsed from request headers
 */
export function createCrowdStrikeClient(
  credentials: TenantCredentials
): CrowdStrikeClient {
  return new CrowdStrikeClientImpl(credentials);
}
