/**
 * CrowdStrike Falcon API Types
 *
 * Type definitions for CrowdStrike Falcon API entities and responses.
 */

// =============================================================================
// Common Types
// =============================================================================

export interface CrowdStrikeResponse<T> {
  meta: ResponseMeta;
  resources: T[];
  errors?: ApiError[];
}

export interface ResponseMeta {
  query_time: number;
  powered_by?: string;
  trace_id: string;
  pagination?: Pagination;
}

export interface Pagination {
  offset?: number;
  limit?: number;
  total?: number;
  after?: string;
}

export interface ApiError {
  code: number;
  message: string;
}

// =============================================================================
// OAuth2 Types
// =============================================================================

export interface OAuth2TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

// =============================================================================
// Host Types
// =============================================================================

export interface Host {
  device_id: string;
  cid: string;
  agent_load_flags?: string;
  agent_local_time?: string;
  agent_version?: string;
  bios_manufacturer?: string;
  bios_version?: string;
  config_id_base?: string;
  config_id_build?: string;
  config_id_platform?: string;
  cpu_signature?: string;
  external_ip?: string;
  hostname?: string;
  first_seen?: string;
  last_seen?: string;
  local_ip?: string;
  mac_address?: string;
  machine_domain?: string;
  major_version?: string;
  minor_version?: string;
  os_version?: string;
  ou?: string[];
  platform_id?: string;
  platform_name?: string;
  product_type?: string;
  product_type_desc?: string;
  provision_status?: string;
  reduced_functionality_mode?: string;
  serial_number?: string;
  site_name?: string;
  status?: string;
  system_manufacturer?: string;
  system_product_name?: string;
  tags?: string[];
  modified_timestamp?: string;
  meta?: {
    version?: string;
  };
  device_policies?: DevicePolicies;
  groups?: string[];
  group_hash?: string;
  kernel_version?: string;
  chassis_type?: string;
  chassis_type_desc?: string;
  connection_ip?: string;
  default_gateway_ip?: string;
  connection_mac_address?: string;
  linux_sensor_mode?: string;
  deployment_type?: string;
}

export interface DevicePolicies {
  prevention?: PolicyInfo;
  sensor_update?: PolicyInfo;
  device_control?: PolicyInfo;
  global_config?: PolicyInfo;
  remote_response?: PolicyInfo;
  firewall?: PolicyInfo;
}

export interface PolicyInfo {
  policy_type?: string;
  policy_id?: string;
  applied?: boolean;
  settings_hash?: string;
  assigned_date?: string;
  applied_date?: string;
  rule_groups?: string[];
}

// =============================================================================
// Detection Types
// =============================================================================

export interface Detection {
  detection_id: string;
  cid: string;
  device: DetectionDevice;
  behaviors: Behavior[];
  behaviors_processed?: string[];
  date_updated?: string;
  first_behavior?: string;
  last_behavior?: string;
  max_confidence?: number;
  max_severity?: number;
  max_severity_displayname?: string;
  seconds_to_resolved?: number;
  seconds_to_triaged?: number;
  show_in_ui?: boolean;
  status?: string;
  assigned_to_name?: string;
  assigned_to_uid?: string;
  email_sent?: boolean;
  hostinfo?: HostInfo;
  quarantined_files?: QuarantinedFile[];
}

export interface DetectionDevice {
  device_id: string;
  cid?: string;
  agent_load_flags?: string;
  agent_local_time?: string;
  agent_version?: string;
  bios_manufacturer?: string;
  bios_version?: string;
  config_id_base?: string;
  config_id_build?: string;
  config_id_platform?: string;
  external_ip?: string;
  hostname?: string;
  first_seen?: string;
  last_seen?: string;
  local_ip?: string;
  mac_address?: string;
  machine_domain?: string;
  major_version?: string;
  minor_version?: string;
  modified_timestamp?: string;
  os_version?: string;
  platform_id?: string;
  platform_name?: string;
  product_type?: string;
  product_type_desc?: string;
  status?: string;
  system_manufacturer?: string;
  system_product_name?: string;
}

export interface Behavior {
  behavior_id: string;
  alleged_filetype?: string;
  cmdline?: string;
  confidence?: number;
  control_graph_id?: string;
  description?: string;
  device_id?: string;
  display_name?: string;
  filename?: string;
  filepath?: string;
  ioc_description?: string;
  ioc_source?: string;
  ioc_type?: string;
  ioc_value?: string;
  md5?: string;
  objective?: string;
  parent_details?: ParentDetails;
  pattern_disposition?: number;
  pattern_disposition_details?: PatternDispositionDetails;
  scenario?: string;
  severity?: number;
  sha256?: string;
  tactic?: string;
  tactic_id?: string;
  technique?: string;
  technique_id?: string;
  template_instance_id?: string;
  timestamp?: string;
  triggering_process_graph_id?: string;
  user_id?: string;
  user_name?: string;
}

export interface ParentDetails {
  parent_cmdline?: string;
  parent_md5?: string;
  parent_process_graph_id?: string;
  parent_sha256?: string;
}

export interface PatternDispositionDetails {
  blocking_unsupported_or_disabled?: boolean;
  bootup_safeguard_enabled?: boolean;
  critical_process_disabled?: boolean;
  detect?: boolean;
  fs_operation_blocked?: boolean;
  handle_operation_downgraded?: boolean;
  inddet_mask?: boolean;
  indicator?: boolean;
  kill_action_failed?: boolean;
  kill_parent?: boolean;
  kill_process?: boolean;
  kill_subprocess?: boolean;
  operation_blocked?: boolean;
  policy_disabled?: boolean;
  process_blocked?: boolean;
  quarantine_file?: boolean;
  quarantine_machine?: boolean;
  registry_operation_blocked?: boolean;
  rooting?: boolean;
  sensor_only?: boolean;
  suspend_parent?: boolean;
  suspend_process?: boolean;
}

export interface HostInfo {
  domain?: string;
  active_directory_dn_display?: string[];
}

export interface QuarantinedFile {
  id?: string;
  paths?: string[];
  sha256?: string;
  state?: string;
}

// =============================================================================
// Incident Types
// =============================================================================

export interface Incident {
  incident_id: string;
  cid: string;
  host_ids?: string[];
  hosts?: IncidentHost[];
  created?: string;
  start?: string;
  end?: string;
  state?: string;
  status?: number;
  name?: string;
  description?: string;
  tags?: string[];
  fine_score?: number;
  assigned_to?: string;
  assigned_to_name?: string;
  users?: string[];
  lm_host_ids?: string[];
  lm_hosts_capped?: boolean;
  modified_timestamp?: string;
  objectives?: string[];
  tactics?: string[];
  techniques?: string[];
}

export interface IncidentHost {
  device_id: string;
  cid?: string;
  hostname?: string;
  platform_name?: string;
}

// =============================================================================
// Alert Types
// =============================================================================

export interface Alert {
  composite_id: string;
  cid: string;
  aggregate_id?: string;
  created_timestamp?: string;
  updated_timestamp?: string;
  type?: string;
  severity?: number;
  severity_name?: string;
  status?: string;
  assigned_to_uid?: string;
  assigned_to_name?: string;
  show_in_ui?: boolean;
  description?: string;
  name?: string;
  product?: string;
  pattern_id?: number;
  tags?: string[];
  device?: AlertDevice;
  behaviors?: AlertBehavior[];
}

export interface AlertDevice {
  device_id?: string;
  hostname?: string;
  platform_name?: string;
  os_version?: string;
  external_ip?: string;
  local_ip?: string;
  mac_address?: string;
}

export interface AlertBehavior {
  behavior_id?: string;
  filename?: string;
  filepath?: string;
  cmdline?: string;
  sha256?: string;
  md5?: string;
  tactic?: string;
  technique?: string;
  objective?: string;
  timestamp?: string;
}

// =============================================================================
// IOC Types
// =============================================================================

export interface IOC {
  id: string;
  type: IOCType;
  value: string;
  action?: string;
  platforms?: string[];
  severity?: string;
  source?: string;
  description?: string;
  tags?: string[];
  applied_globally?: boolean;
  host_groups?: string[];
  expiration?: string;
  expired?: boolean;
  deleted?: boolean;
  from_parent?: boolean;
  created_on?: string;
  created_by?: string;
  modified_on?: string;
  modified_by?: string;
  metadata?: Record<string, unknown>;
}

export type IOCType = 'sha256' | 'md5' | 'domain' | 'ipv4' | 'ipv6';

export type IOCAction = 'no_action' | 'allow' | 'detect' | 'prevent' | 'prevent_no_ui';

export interface IOCCreateInput {
  type: IOCType;
  value: string;
  action: IOCAction;
  platforms: string[];
  severity?: string;
  description?: string;
  tags?: string[];
  host_groups?: string[];
  expiration?: string;
  applied_globally?: boolean;
  source?: string;
}

// =============================================================================
// Vulnerability Types
// =============================================================================

export interface Vulnerability {
  id: string;
  cid: string;
  aid?: string;
  created_timestamp?: string;
  updated_timestamp?: string;
  status?: string;
  cve?: CVEInfo;
  host_info?: VulnerabilityHostInfo;
  remediation?: Remediation;
  apps?: VulnerableApp[];
  suppression_info?: SuppressionInfo;
}

export interface CVEInfo {
  id: string;
  base_score?: number;
  severity?: string;
  exploit_status?: number;
  exploit_status_name?: string;
  exprt_rating?: string;
  description?: string;
  published_date?: string;
  cisa_info?: CISAInfo;
  spotlight_published_date?: string;
  actors?: string[];
  vector?: string;
  references?: string[];
}

export interface CISAInfo {
  due_date?: string;
  is_cisa_kev?: boolean;
}

export interface VulnerabilityHostInfo {
  hostname?: string;
  local_ip?: string;
  machine_domain?: string;
  os_version?: string;
  ou?: string;
  site_name?: string;
  system_manufacturer?: string;
  tags?: string[];
  platform?: string;
  instance_id?: string;
  service_provider?: string;
  service_provider_account_id?: string;
  groups?: HostGroup[];
}

export interface Remediation {
  ids?: string[];
  entities?: RemediationEntity[];
}

export interface RemediationEntity {
  id?: string;
  reference?: string;
  title?: string;
  action?: string;
  link?: string;
  vendor_url?: string;
}

export interface VulnerableApp {
  product_name_version?: string;
  sub_status?: string;
  remediation?: {
    ids?: string[];
  };
  evaluation_logic?: {
    id?: string;
    aid?: string;
  };
}

export interface SuppressionInfo {
  is_suppressed?: boolean;
  reason?: string;
}

// =============================================================================
// Host Group Types
// =============================================================================

export interface HostGroup {
  id: string;
  cid?: string;
  name: string;
  description?: string;
  group_type: 'dynamic' | 'static' | 'staticByID';
  assignment_rule?: string;
  created_by?: string;
  created_timestamp?: string;
  modified_by?: string;
  modified_timestamp?: string;
}

export interface HostGroupCreateInput {
  name: string;
  group_type: 'dynamic' | 'static' | 'staticByID';
  description?: string;
  assignment_rule?: string;
}

// =============================================================================
// Policy Types
// =============================================================================

export interface Policy {
  id: string;
  cid?: string;
  name: string;
  description?: string;
  platform_name: string;
  enabled: boolean;
  created_by?: string;
  created_timestamp?: string;
  modified_by?: string;
  modified_timestamp?: string;
  groups?: PolicyGroup[];
  ioa_rule_groups?: IoaRuleGroup[];
  settings?: PolicySettings;
}

export interface PolicyGroup {
  id: string;
  name?: string;
}

export interface IoaRuleGroup {
  id: string;
  name?: string;
  enabled?: boolean;
  rule_ids?: string[];
}

export interface PolicySettings {
  prevention?: Record<string, PreventionSetting>;
  sensor_update?: SensorUpdateSettings;
  device_control?: DeviceControlSettings;
}

export interface PreventionSetting {
  value: {
    enabled?: boolean;
    detection?: string;
    prevention?: string;
  };
}

export interface SensorUpdateSettings {
  build?: string;
  uninstall_protection?: string;
  sensor_version?: string;
  stage?: string;
  scheduler?: {
    enabled?: boolean;
    schedules?: ScheduleItem[];
  };
}

export interface ScheduleItem {
  days?: number[];
  start?: string;
  end?: string;
  timezone?: string;
}

export interface DeviceControlSettings {
  classes?: DeviceClass[];
  end_user_notification?: string;
  enforcement_mode?: string;
  custom_notifications?: CustomNotification;
}

export interface DeviceClass {
  id: string;
  action?: string;
  exceptions?: DeviceException[];
}

export interface DeviceException {
  id?: string;
  action?: string;
  combined_id?: string;
  vendor_name?: string;
  product_name?: string;
  serial_number?: string;
}

export interface CustomNotification {
  overall_message?: string;
  blocking_message?: string;
  restricted_message?: string;
}

// =============================================================================
// Real-Time Response Types
// =============================================================================

export interface RTRSession {
  session_id: string;
  scripts?: RTRScript[];
  existing_aid_sessions?: number;
  pwd?: string;
  created_at?: string;
  offline_queued?: boolean;
  complete?: boolean;
}

export interface RTRScript {
  id: string;
  name?: string;
  description?: string;
  permission_type?: string;
  content?: string;
  platform?: string[];
  sha256?: string;
  size?: number;
  created_by?: string;
  created_timestamp?: string;
  modified_by?: string;
  modified_timestamp?: string;
}

export interface RTRCommandResult {
  cloud_request_id: string;
  session_id: string;
  task_id?: string;
  complete: boolean;
  stdout?: string;
  stderr?: string;
  base_command?: string;
  aid?: string;
  errors?: ApiError[];
  queued_command_offline?: boolean;
}

export interface RTRFileInfo {
  id: string;
  cloud_request_id?: string;
  session_id?: string;
  name: string;
  sha256?: string;
  size?: number;
  created_at?: string;
  deleted_at?: string;
}

// =============================================================================
// CrowdScore Types
// =============================================================================

export interface CrowdScore {
  id: string;
  cid?: string;
  score?: number;
  timestamp?: string;
  adjusted_score?: number;
}

// =============================================================================
// Behavior Types (for Incident behaviors)
// =============================================================================

export interface IncidentBehavior {
  behavior_id: string;
  incident_ids?: string[];
  aid?: string;
  cid?: string;
  timestamp?: string;
  cmdline?: string;
  filename?: string;
  filepath?: string;
  ioc_type?: string;
  ioc_value?: string;
  ioc_source?: string;
  ioc_description?: string;
  md5?: string;
  sha256?: string;
  pattern_id?: number;
  severity?: number;
  confidence?: number;
  objective?: string;
  tactic?: string;
  technique?: string;
  user_id?: string;
  user_name?: string;
  parent_details?: ParentDetails;
}
