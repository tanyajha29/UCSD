/**
 * Strict TypeScript types for UCSD analysis models, conflict reports, and API responses.
 */

export type EvidenceLevel =
  | 'STRONG_STATIC_ASSOCIATION'
  | 'REGISTRATION_PATTERN_UUID_UNRESOLVED'
  | 'UUID_CANDIDATE_ONLY';

export type UnresolvedReason =
  | 'CROSS_METHOD_SERVICE_OBJECT'
  | 'FIELD_BASED_SERVICE_OBJECT'
  | 'CROSS_METHOD_UUID'
  | 'FIELD_BASED_UUID'
  | 'DYNAMIC_UUID_EXPRESSION'
  | 'SERVICE_CONSTRUCTED_WITHOUT_LOCAL_ADD_SERVICE'
  | 'NO_REGISTRATION_CALL_SITE'
  | 'REGISTER_CLOBBERED_BEFORE_USE';

export type ConflictCondition =
  | 'STRONG_DUPLICATE_STATIC_REGISTRATION'
  | 'DUPLICATE_CANDIDATE_NO_REGISTRATION'
  | 'KNOWN_ASSIGNED_STANDARD_MATCH'
  | 'KNOWN_SYSTEM_OR_VENDOR_MATCH'
  | 'UNRESOLVED_REGISTRATION_OVERLAP'
  | 'UNKNOWN_UNCONFLICTED';

export interface DashboardStats {
  total_apks: number;
  successful_analyses: number;
  failed_analyses: number;
  running_analyses: number;
  candidate_only: number;
  strong_static_registrations: number;
  unresolved_patterns: number;
  total_comparisons: number;
  cross_apk_conflicts: number;
  recent_analyses: AnalysisSummary[];
  recent_errors: { id: string; file_name: string; error_message: string; created_at: string }[];
}

export interface AnalysisSummary {
  id: string;
  file_name: string;
  file_size_bytes: number;
  sha256?: string;
  package_name?: string;
  version_code?: number;
  version_name?: string;
  status: 'running' | 'success' | 'partial' | 'error';
  error_message?: string;
  candidate_count: number;
  strong_count: number;
  unresolved_count: number;
  report_json_path?: string;
  report_html_path?: string;
  created_at: string;
  updated_at: string;
}

export interface PaginatedAnalyses {
  items: AnalysisSummary[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface TraceStep {
  step_index: number;
  step_type: string;
  instruction_offset: number;
  opcode: string;
  details: Record<string, any>;
}

export interface ServiceConstructionSite {
  dex_file: string;
  class_name: string;
  method_name: string;
  descriptor: string;
  instruction_offset: number;
  service_register: number;
  uuid_register: number;
  service_type_register?: number;
  resolved_uuid?: string;
  unresolved_reason?: UnresolvedReason;
}

export interface AddServiceCallSite {
  dex_file: string;
  class_name: string;
  method_name: string;
  descriptor: string;
  instruction_offset: number;
  server_register: number;
  service_register: number;
  is_service_resolved_locally: boolean;
  unresolved_reason?: UnresolvedReason;
}

export interface RegistrationFinding {
  evidence_level: EvidenceLevel;
  normalized_uuid?: string;
  dex_file: string;
  class_name: string;
  method_name: string;
  descriptor: string;
  diagnosis: string;
  construction_site?: ServiceConstructionSite;
  registration_site?: AddServiceCallSite;
  trace_steps: TraceStep[];
  unresolved_reason?: UnresolvedReason;
}

export interface RegistrationAnalysisResult {
  has_gatt_registrations: boolean;
  total_add_service_calls: number;
  total_service_constructions: number;
  strong_associations_count: number;
  unresolved_patterns_count: number;
  candidate_only_count: number;
  findings: RegistrationFinding[];
  blind_spots_and_limitations: string[];
}

export interface KnowledgeBaseEntry {
  normalized_uuid: string;
  name: string;
  identifier_type: string;
  source_name: string;
  source_url?: string;
  retrieval_date?: string;
  description?: string;
  analyst_notes?: string;
}

export interface CrossAPKEvidence {
  package_name?: string;
  version_code?: number;
  version_name?: string;
  file_name: string;
  sha256: string;
  evidence_level: string;
  class_name?: string;
  method_name?: string;
  descriptor?: string;
  dex_file?: string;
  instruction_offset?: number;
  diagnosis: string;
}

export interface UUIDConflictAssessment {
  normalized_uuid: string;
  condition: ConflictCondition;
  is_proven: boolean;
  is_proven_service_conflict?: boolean;
  explanation: string;
  knowledge_base_match?: KnowledgeBaseEntry;
  participating_apks: CrossAPKEvidence[];
}

export interface SingleAPKKnowledgeAssessment {
  total_candidates_checked: number;
  known_standard_matches_count: number;
  known_system_vendor_matches_count: number;
  unknown_candidates_count: number;
  findings: UUIDConflictAssessment[];
}

export interface UUIDEvidenceLocation {
  dex_file: string;
  class_name?: string;
  method_name?: string;
  descriptor?: string;
  instruction_offset?: number;
  opcode?: string;
  in_string_pool: boolean;
}

export interface UUIDCandidate {
  raw_string: string;
  normalized_uuid: string;
  format_type: string;
  occurrence_count: number;
  evidence: UUIDEvidenceLocation[];
}

export interface BLEAnalysisResult {
  has_bluetooth_permissions: boolean;
  permissions_requested: string[];
  classes_referenced: string[];
  methods_referenced: string[];
  is_gatt_client: boolean;
  is_gatt_server: boolean;
  is_le_scanner: boolean;
  is_le_advertiser: boolean;
  uuid_candidates: UUIDCandidate[];
}

export interface ManifestMetadata {
  package_name?: string;
  version_code?: number;
  version_name?: string;
  min_sdk_version?: number;
  target_sdk_version?: number;
  max_sdk_version?: number;
  requested_permissions: string[];
  declared_permissions: string[];
  activities: string[];
  services: string[];
  receivers: string[];
  providers: string[];
  main_activity?: string;
}

export interface DEXInfo {
  name: string;
  sha256: string;
  size_bytes: number;
}

export interface APKMetadata {
  file_path: string;
  file_name: string;
  file_size_bytes: number;
  sha256: string;
  is_valid_zip: boolean;
  is_multidex: boolean;
  dex_count: number;
  dex_files: DEXInfo[];
  manifest?: ManifestMetadata;
  ble_analysis?: BLEAnalysisResult;
  registration_analysis?: RegistrationAnalysisResult;
  knowledge_base_assessment?: SingleAPKKnowledgeAssessment;
}

export interface AnalysisReport {
  status: 'success' | 'partial' | 'error';
  timestamp: string;
  target: string;
  analyzer_version: string;
  knowledge_base_version?: string;
  metadata?: APKMetadata;
  ble_analysis?: BLEAnalysisResult;
  registration_analysis?: RegistrationAnalysisResult;
  knowledge_base_assessment?: SingleAPKKnowledgeAssessment;
  limitations: string[];
  html_report_path?: string;
  error?: { error_type: string; message: string };
}

export interface CrossAPKConflictReport {
  total_apks_analyzed: number;
  total_unique_uuids_evaluated: number;
  strong_duplicate_static_registrations_count: number;
  proven_registration_conflicts_count: number;
  duplicate_candidates_unregistered_count: number;
  known_standard_matches_count: number;
  known_system_vendor_matches_count: number;
  unknown_uuids_count: number;
  assessments: UUIDConflictAssessment[];
  knowledge_base_metadata: {
    knowledge_base_version: string;
    total_entries: number;
    last_updated: string;
  };
  methodology_and_limitations: string[];
}

export interface ComparisonRecord {
  id: string;
  title: string;
  analysis_ids: string[];
  target_count: number;
  strong_duplicates_count: number;
  proven_conflicts_count: number;
  report_data?: CrossAPKConflictReport;
  created_at: string;
}

export interface SystemHealth {
  status: string;
  analyzer_version: string;
  timestamp: string;
  database: string;
  storage: string;
  knowledge_base: {
    status: string;
    version: string;
    total_entries: number;
  };
  available_capabilities: string[];
}
