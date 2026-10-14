export type ArtifactCategory = 'DOCUMENT' | 'DATABASE_LOG' | 'PHOTO_MEDIA' | 'SYSTEM_TRACE' | 'BINARY_ARCHIVE';
export type PriorityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type RecoveryStatus = 'FULLY_RECOVERED' | 'PARTIALLY_RECOVERED' | 'CORRUPTED' | 'UNRECOVERABLE';
export type ReconstructionMethod = 'CONTIGUOUS' | 'BIFRAGMENT_GAP' | 'NONE';

/**
 * Deterministic 100-point rubric breakdown.
 * Note: These status thresholds (85-100: FULLY_RECOVERED, 50-84: PARTIALLY_RECOVERED, 
 * 20-49: CORRUPTED, 0-19: UNRECOVERABLE) are our prototype policy, 
 * not an established forensic standard.
 */
export interface ConfidenceBreakdown {
  header_validity: number; // max 20
  footer_validity: number; // max 20
  structural_validation: number; // max 30
  size_plausibility: number; // max 15
  reconstruction_integrity: number; // max 15
  total: number; // max 100
}

export interface ValidationCheck {
  name: string;
  detail: string;
  passed: boolean;
}

export interface ValidationResult {
  valid: boolean;
  error?: string;
  checks?: ValidationCheck[];
}

export type FragmentType = 'VERIFIED' | 'RECONSTRUCTED_GAP' | 'MISSING';

export interface Fragment {
  id: string;
  start_offset: number;
  end_offset: number;
  type: FragmentType;
  source_disk?: string;
}

export interface AIExplanation {
  summary: string;
  details: string[];
  cached?: boolean;
  available?: boolean;
  assessment?: string;
  priority?: PriorityLevel;
  why_it_matters?: string;
  recovery_limitation?: string;
  recommended_next_step?: string;
  source?: string;
  facts?: Record<string, any>;
}

export interface Artifact {
  id: string;
  filename: string;
  mime_type: string;
  category: ArtifactCategory;
  priority: PriorityLevel;
  confidence_score: number;
  confidence_breakdown: ConfidenceBreakdown;
  status: RecoveryStatus;
  verified_bytes: number;
  reconstructed_bytes: number;
  missing_bytes: number;
  reconstruction_method: ReconstructionMethod;
  validation: ValidationResult;
  fragments: Fragment[];
  preview_text: string;
  ai_summary: AIExplanation | null;
}

export interface Case {
  id: string;
  name: string;
  description: string;
  artifacts: Artifact[];
}

export interface GroundTruthExpectedArtifact {
  id: string;
  filename: string;
  scenario: 'CLEAN_CONTIGUOUS' | 'DELETED' | 'FRAGMENTED' | 'BIFRAGMENT_GAP' | 'CORRUPTED' | 'UNRECOVERABLE';
  expected_status: RecoveryStatus;
  original_sha256: string;
  total_bytes: number;
}

export interface GroundTruth {
  case_id: string;
  image_filename: string;
  expected_artifacts: GroundTruthExpectedArtifact[];
}

export interface ForensicFragment {
  fragment_id: string;
  offset: number;
  length: number;
  end_offset: number;
  status: string;
  source: string;
  format: string;
  verified_bytes: number;
  reconstructed_bytes: number;
  missing_bytes: number;
  validation_status: string;
  relationships?: {
    source_fragment_id: string;
    target_fragment_id: string;
    relationship_type: string;
    details?: Record<string, any>;
  }[];
}

export interface DamageRegion {
  region_id: string;
  start_offset: number;
  end_offset: number;
  length: number;
  type: string;
  status: string;
}

export interface ReconstructionStep {
  step_id: string;
  method: string;
  gap_start?: number;
  gap_end?: number;
  gap_size?: number;
  result: string;
  verified_bytes: number;
  reconstructed_bytes: number;
  missing_bytes: number;
}

export interface InvestigationContext {
  case_name: string;
  investigator: string;
  evidence_description: string;
  notes: string;
  created_at: string;
}

export interface SingleFileRecoveryResult {
  file_id: string;
  run_id?: string;
  original_filename: string;
  recovered_filename: string;
  format: string;
  status: RecoveryStatus;
  confidence_score: number;
  verified_bytes: number;
  reconstructed_bytes: number;
  missing_bytes: number;
  reconstruction_method: string;
  validation_status: string;
  is_downloadable: boolean;
  download_url: string;
  content_preview?: string | null;
  score_breakdown: ConfidenceBreakdown;
  validation_details?: Record<string, any>;
  fragments?: ForensicFragment[];
  damage_regions?: DamageRegion[];
  reconstruction_steps?: ReconstructionStep[];
  total_input_bytes?: number;
  provenance?: Record<string, any>;
  context?: InvestigationContext;
}

/**
 * Milestone 3.5: Grounded Evidence Interpretation Types.
 * Faithfully mirror backend contracts in backend/app/models/interpretation.py.
 */

export type AuthoritativeRecoveryStatus =
  | 'FULLY_RECOVERED'
  | 'PARTIALLY_RECOVERED'
  | 'CORRUPTED'
  | 'UNRECOVERABLE';

export type AuthoritativeClusterClassification =
  | 'ISOLATED'
  | 'COEXTENSIVE_SET'
  | 'CONTAINMENT_TREE'
  | 'OVERLAP_SPAN'
  | 'MIXED';

export type InterpretationSource =
  | 'DETERMINISTIC_RULES'
  | 'GEMINI_1_5_FLASH';

export interface DeterministicArtifactFacts {
  artifact_id: string;
  run_id?: string | null;
  case_id?: string | null;
  evidence_file_id?: string | null;
  filename: string;
  format: string;
  category: string;
  status: AuthoritativeRecoveryStatus;
  confidence_score: number;
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  verified_bytes: number;
  reconstructed_bytes: number;
  missing_bytes: number;
  total_input_bytes?: number | null;
  reconstruction_method: string;
  validation_status: string;
  damage_region_count: number;
  is_ambiguous: boolean;
  evidence_start?: number | null;
  evidence_end?: number | null;
}

export interface DeterministicRelationshipFact {
  edge_id: string;
  source_node_id: string;
  target_node_id: string;
  relationship_type: 'COEXTENSIVE' | 'CONTAINS' | 'CONTAINED_BY' | 'OVERLAPS';
  evidence_file_id: string;
  evidence_basis: string;
  overlap_start?: number | null;
  overlap_end?: number | null;
  overlap_bytes: number;
}

export interface DeterministicClusterFacts {
  cluster_id: string;
  case_id: string;
  evidence_file_id?: string | null;
  cluster_start: number;
  cluster_end?: number | null;
  bounding_span_bytes?: number | null;
  unique_physical_bytes?: number | null;
  bounded_physical_bytes: number;
  has_unbounded_candidate: boolean;
  relationship_classification: AuthoritativeClusterClassification;
  has_ambiguity: boolean;
  total_nodes: number;
  coextensive_candidate_count: number;
  containment_edge_count: number;
  overlap_edge_count: number;
  competing_format_count: number;
  member_formats: string[];
  member_node_ids: string[];
  max_confidence_score: number;
  highest_priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  candidate_aggregate_verified_bytes: number;
  candidate_aggregate_reconstructed_bytes: number;
  candidate_aggregate_missing_bytes: number;
  status_distribution: Record<string, number>;
  total_damage_regions: number;
}

export interface DeterministicCaseFacts {
  case_id: string;
  total_evidence_buffers: number;
  total_artifacts: number;
  total_nodes: number;
  total_clusters: number;
  case_physical_coverage_bytes?: number | null;
  case_coverage_is_complete: boolean;
  candidate_aggregate_verified_bytes: number;
  candidate_aggregate_reconstructed_bytes: number;
  candidate_aggregate_missing_bytes: number;
  unscoped_candidate_count: number;
  unscoped_aggregate_verified_bytes: number;
  format_distribution: Record<string, number>;
  status_distribution: Record<string, number>;
  priority_distribution: Record<string, number>;
  cluster_classification_distribution: Record<string, number>;
  candidate_cap_enforced: boolean;
  total_discovered_candidates: number;
  candidates_omitted: number;
  graph_is_complete: boolean;
}

export interface ArtifactInterpretationContext {
  facts: DeterministicArtifactFacts;
  content_preview?: string | null;
  cluster_context?: DeterministicClusterFacts | null;
}

export interface ClusterInterpretationContext {
  facts: DeterministicClusterFacts;
  nodes: DeterministicArtifactFacts[];
  relationships: DeterministicRelationshipFact[];
}

export interface CaseInterpretationContext {
  facts: DeterministicCaseFacts;
  cluster_facts: DeterministicClusterFacts[];
}

export interface ProviderInterpretationOutput {
  summary: string;
  assessment: string;
  structural_context: string;
  limitations: string;
  recommended_next_steps: string;
  details: string[];
}

export interface GroundedArtifactInterpretation {
  facts: DeterministicArtifactFacts;
  interpretation: ProviderInterpretationOutput;
  source: InterpretationSource;
  cached: boolean;
  generated_at: string;
}

export interface GroundedClusterInterpretation {
  facts: DeterministicClusterFacts;
  relationships: DeterministicRelationshipFact[];
  interpretation: ProviderInterpretationOutput;
  source: InterpretationSource;
  cached: boolean;
  generated_at: string;
  cluster_fingerprint: string;
}

export interface GroundedCaseInterpretation {
  facts: DeterministicCaseFacts;
  interpretation: ProviderInterpretationOutput;
  source: InterpretationSource;
  cached: boolean;
  generated_at: string;
  case_graph_fingerprint: string;
}
