export type Platform = "Oracle" | "PostgreSQL" | "Sybase ASE" | "MySQL";
export type Environment = "Production" | "Pre-production" | "Development";
export type Health = "Healthy" | "Attention" | "Critical" | "Offline";
export type Severity = "Critical" | "High" | "Medium" | "Low";
export type FindingStatus = "Open" | "In remediation" | "Risk accepted" | "Resolved" | "False positive";
export type ControlStatus = "Passed" | "Needs attention" | "Failed" | "Pending" | "Superseded";
export type ReviewOutcome = "passed" | "failed" | "not_applicable";

export interface DatabaseAsset {
  id: string;
  name: string;
  platform: Platform;
  version: string;
  environment: Environment;
  region: string;
  owner: string;
  businessService: string;
  controlCoverage: number;
  criticalFindings: number;
  lastScan: string;
  health: Health;
  sensitiveObjects: number;
}

export interface Assessment {
  id: string;
  name: string;
  domain: "Encryption" | "Data protection" | "Access security" | "Data masking";
  platform: Platform | "All platforms";
  status: ControlStatus;
  score: number | null;
  passed: number;
  warnings: number;
  failed: number;
  evidence: number;
  controlCount?: number;
  automatedControls?: number;
  manualControlsPending?: number;
  collectionCoverage?: number;
  collectionErrors?: number;
  collectionStatus?: string;
  lastRun: string;
}

export interface AssessmentReviewDecision {
  outcome: ReviewOutcome;
  rationale: string;
}

export interface AssessmentReviewDefinition {
  id: string;
  controlId: string;
  domain: Assessment["domain"];
  title: string;
  objective: string;
  severity: Severity;
  assessmentMode: string;
  manualEvidenceRequirements: readonly string[];
  remediationGuidance: string;
}

export interface AssessmentCollectionResult {
  outcome: string;
  rationale: string;
  evidenceCount: number;
}

export type AssessmentObservation = Readonly<
  Record<string, string | number | boolean | null>
>;

export interface AssessmentReviewControl {
  definition: AssessmentReviewDefinition;
  collectionResult: AssessmentCollectionResult | null;
  evidenceIds: readonly string[];
  observations: readonly AssessmentObservation[];
  decision: AssessmentReviewDecision | null;
  allowedOutcomes: readonly ReviewOutcome[];
}

export interface AssessmentReview {
  assessment: Assessment;
  assetName: string;
  controls: readonly AssessmentReviewControl[];
  decidedCount: number;
  totalControls: number;
  readyToFinalize: boolean;
  blockingReasons: readonly string[];
}

export interface Finding {
  id: string;
  assessmentId?: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  platform: Platform;
  asset: string;
  control: string;
  owner: string;
  dueDate: string;
  dueAt?: string;
  evidence: string;
  remediation: string;
}

export interface SensitiveColumn {
  id: string;
  asset: string;
  platform: Platform;
  schema: string;
  table: string;
  column: string;
  classification: "Restricted" | "Confidential" | "Internal";
  dataType: string;
  confidence: number;
  protection: "Masked" | "Encrypted" | "Tokenized" | "Unprotected" | "Unknown";
}

export interface AccessReview {
  id: string;
  principal: string;
  principalType: "Human" | "Service account" | "Database role";
  platform: Platform;
  asset: string;
  access: string;
  risk: Severity;
  lastUsed: string;
  recommendation: string;
  checkedAt?: string;
  reviewer?: string;
  reviewStatus?: "Draft" | "In review" | "Approved" | "Remediation required" | "Closed";
  scanScope?: string;
}

export interface MaskingPolicy {
  id: string;
  name: string;
  classification: string;
  technique: string;
  coverage: number;
  datasets: number;
  environment: string;
  status: "Archived" | "Validated" | "Execution recorded" | "Approved" | "Pilot" | "Draft";
  lastValidated: string;
  workflowStatus?: "draft" | "approved" | "execution_recorded" | "validated";
  lastNote?: string;
  executionReference?: string;
  isBuiltinLocalCopy?: boolean;
  copyStatus?: "queued" | "running" | "retry_pending" | "failed" | "automated_checks_passed";
  sourceDatabase?: string;
  targetDatabase?: string;
  rowCap?: number;
  tablesCopied?: number;
  rowsCopied?: number;
  columnsMasked?: number;
  valuesMasked?: number;
  automatedChecksPassed?: boolean;
  archived?: boolean;
  archivedAt?: string;
}

export interface EvidenceRecord {
  id: string;
  assessmentId?: string;
  control: string;
  asset: string;
  platform: Platform;
  source: string;
  collectedAt: string;
  integrity: "Digest recorded" | "Missing digest";
  retention: string;
}

export interface Connector {
  id: string;
  assetId?: string;
  name: string;
  platform: Platform;
  version: string;
  region: string;
  assets: number;
  status: "Online" | "Degraded" | "Offline";
  lastHeartbeat: string;
  nextScan: string;
  serviceAccount: string;
  releaseChannel: "Stable" | "Controlled";
  capabilities?: string[];
}

export interface ControlDomain {
  name: string;
  score: number;
  scoreAvailable?: boolean;
  change: number;
  controls: number;
  findings: number;
}

export const assets: readonly DatabaseAsset[] = [
  {
    id: "DB-ORA-001",
    name: "ora-payments-prd-01",
    platform: "Oracle",
    version: "19c RU 19.24",
    environment: "Production",
    region: "Mumbai DC-1",
    owner: "Payments Platform",
    businessService: "Real-time payments",
    controlCoverage: 91,
    criticalFindings: 0,
    lastScan: "12 Aug 2026, 09:42 IST",
    health: "Healthy",
    sensitiveObjects: 184,
  },
  {
    id: "DB-PG-014",
    name: "pg-customer360-prd",
    platform: "PostgreSQL",
    version: "16.4",
    environment: "Production",
    region: "AWS ap-south-1",
    owner: "Customer Data",
    businessService: "Customer 360",
    controlCoverage: 76,
    criticalFindings: 1,
    lastScan: "12 Aug 2026, 09:18 IST",
    health: "Critical",
    sensitiveObjects: 326,
  },
  {
    id: "DB-SYB-003",
    name: "ase-treasury-prd-02",
    platform: "Sybase ASE",
    version: "16.0 SP04 PL06",
    environment: "Production",
    region: "Pune DC-2",
    owner: "Treasury Technology",
    businessService: "Liquidity management",
    controlCoverage: 68,
    criticalFindings: 1,
    lastScan: "12 Aug 2026, 08:55 IST",
    health: "Attention",
    sensitiveObjects: 96,
  },
  {
    id: "DB-ORA-008",
    name: "ora-risk-dwh-uat",
    platform: "Oracle",
    version: "19c RU 19.23",
    environment: "Pre-production",
    region: "Mumbai DC-1",
    owner: "Enterprise Risk",
    businessService: "Risk analytics",
    controlCoverage: 84,
    criticalFindings: 0,
    lastScan: "12 Aug 2026, 07:31 IST",
    health: "Healthy",
    sensitiveObjects: 208,
  },
  {
    id: "DB-PG-021",
    name: "pg-digital-dev-04",
    platform: "PostgreSQL",
    version: "15.8",
    environment: "Development",
    region: "Azure Central India",
    owner: "Digital Channels",
    businessService: "Mobile banking",
    controlCoverage: 73,
    criticalFindings: 0,
    lastScan: "11 Aug 2026, 23:40 IST",
    health: "Attention",
    sensitiveObjects: 72,
  },
  {
    id: "DB-SYB-009",
    name: "ase-opsarchive-prd",
    platform: "Sybase ASE",
    version: "16.0 SP03 PL13",
    environment: "Production",
    region: "Pune DC-2",
    owner: "Core Operations",
    businessService: "Operations archive",
    controlCoverage: 51,
    criticalFindings: 2,
    lastScan: "11 Aug 2026, 18:12 IST",
    health: "Offline",
    sensitiveObjects: 141,
  },
] as const;

export const assessments: readonly Assessment[] = [
  { id: "ASM-1001", name: "Encryption at rest", domain: "Encryption", platform: "All platforms", status: "Failed", score: 71, passed: 18, warnings: 4, failed: 3, evidence: 25, lastRun: "12 Aug, 09:42" },
  { id: "ASM-1002", name: "TLS and transport security", domain: "Encryption", platform: "All platforms", status: "Needs attention", score: 83, passed: 16, warnings: 3, failed: 1, evidence: 20, lastRun: "12 Aug, 09:38" },
  { id: "ASM-1003", name: "Privileged role governance", domain: "Access security", platform: "Oracle", status: "Needs attention", score: 78, passed: 24, warnings: 5, failed: 1, evidence: 30, lastRun: "12 Aug, 09:31" },
  { id: "ASM-1004", name: "Authentication and login policy", domain: "Access security", platform: "PostgreSQL", status: "Failed", score: 64, passed: 11, warnings: 4, failed: 3, evidence: 18, lastRun: "12 Aug, 09:18" },
  { id: "ASM-1005", name: "Audit configuration", domain: "Data protection", platform: "Sybase ASE", status: "Needs attention", score: 69, passed: 10, warnings: 4, failed: 1, evidence: 15, lastRun: "12 Aug, 08:55" },
  { id: "ASM-1006", name: "Sensitive-data classification", domain: "Data protection", platform: "All platforms", status: "Passed", score: 92, passed: 21, warnings: 2, failed: 0, evidence: 23, lastRun: "12 Aug, 08:34" },
  { id: "ASM-1007", name: "Non-production masking", domain: "Data masking", platform: "Oracle", status: "Passed", score: 96, passed: 14, warnings: 1, failed: 0, evidence: 15, lastRun: "12 Aug, 07:31" },
  { id: "ASM-1008", name: "Masking policy coverage", domain: "Data masking", platform: "PostgreSQL", status: "Needs attention", score: 74, passed: 9, warnings: 4, failed: 1, evidence: 14, lastRun: "11 Aug, 23:40" },
] as const;

export const findings: readonly Finding[] = [
  { id: "FND-2041", title: "Unencrypted production tablespace", severity: "Critical", status: "In remediation", platform: "Sybase ASE", asset: "ase-opsarchive-prd", control: "ENC-AT-01", owner: "Core Operations", dueDate: "15 Aug 2026", evidence: "Collector query and configuration fingerprint", remediation: "Enable database encryption, rotate the master key, and validate backup recoverability." },
  { id: "FND-2037", title: "Superuser service account uses password authentication", severity: "Critical", status: "Open", platform: "PostgreSQL", asset: "pg-customer360-prd", control: "IAM-AU-04", owner: "Customer Data", dueDate: "14 Aug 2026", evidence: "pg_authid and pg_hba.conf metadata", remediation: "Move the integration to certificate authentication and remove unnecessary superuser membership." },
  { id: "FND-2035", title: "Audit log retention below policy", severity: "High", status: "Open", platform: "Sybase ASE", asset: "ase-treasury-prd-02", control: "LOG-RT-03", owner: "Treasury Technology", dueDate: "20 Aug 2026", evidence: "Audit segment configuration", remediation: "Increase audit retention to 365 days and validate forwarding to the enterprise SIEM." },
  { id: "FND-2032", title: "PUBLIC retains CREATE privilege", severity: "High", status: "In remediation", platform: "PostgreSQL", asset: "pg-digital-dev-04", control: "IAM-LP-07", owner: "Digital Channels", dueDate: "22 Aug 2026", evidence: "Namespace ACL snapshot", remediation: "Revoke CREATE from PUBLIC and grant it to the approved deployment role." },
  { id: "FND-2029", title: "TDE wallet auto-login exception has expired", severity: "Medium", status: "Risk accepted", platform: "Oracle", asset: "ora-risk-dwh-uat", control: "KEY-GV-06", owner: "Enterprise Risk", dueDate: "31 Aug 2026", evidence: "Wallet status and exception register", remediation: "Replace the auto-login wallet with a centrally managed key activation workflow." },
  { id: "FND-2025", title: "Dormant privileged account retained", severity: "Medium", status: "Open", platform: "Oracle", asset: "ora-payments-prd-01", control: "IAM-LC-02", owner: "Payments Platform", dueDate: "26 Aug 2026", evidence: "DBA_USERS and unified audit trail", remediation: "Lock the account, validate ownership, and remove it after the approved quarantine period." },
  { id: "FND-2018", title: "Masking validation evidence incomplete", severity: "Low", status: "Resolved", platform: "PostgreSQL", asset: "pg-digital-dev-04", control: "MSK-VL-05", owner: "Digital Channels", dueDate: "10 Aug 2026", evidence: "Masking job execution record", remediation: "Attach referential-integrity and re-identification test results to the release evidence." },
] as const;

export const sensitiveColumns: readonly SensitiveColumn[] = [
  { id: "CLS-901", asset: "pg-customer360-prd", platform: "PostgreSQL", schema: "customer", table: "profile", column: "national_id", classification: "Restricted", dataType: "varchar(32)", confidence: 99, protection: "Tokenized" },
  { id: "CLS-902", asset: "ora-payments-prd-01", platform: "Oracle", schema: "PAYMENTS", table: "BENEFICIARY", column: "ACCOUNT_NUMBER", classification: "Restricted", dataType: "VARCHAR2(34)", confidence: 98, protection: "Encrypted" },
  { id: "CLS-903", asset: "ase-treasury-prd-02", platform: "Sybase ASE", schema: "dbo", table: "counterparty", column: "tax_identifier", classification: "Restricted", dataType: "varchar(24)", confidence: 97, protection: "Unprotected" },
  { id: "CLS-904", asset: "ora-risk-dwh-uat", platform: "Oracle", schema: "RISK_STAGE", table: "BORROWER", column: "EMAIL_ADDRESS", classification: "Confidential", dataType: "VARCHAR2(254)", confidence: 96, protection: "Masked" },
  { id: "CLS-905", asset: "pg-digital-dev-04", platform: "PostgreSQL", schema: "mobile", table: "device_registration", column: "phone_number", classification: "Confidential", dataType: "text", confidence: 94, protection: "Masked" },
  { id: "CLS-906", asset: "ase-opsarchive-prd", platform: "Sybase ASE", schema: "dbo", table: "operator_event", column: "user_ip", classification: "Internal", dataType: "varchar(45)", confidence: 88, protection: "Unprotected" },
] as const;

export const accessReviews: readonly AccessReview[] = [
  { id: "ACC-311", principal: "svc_customer_export", principalType: "Service account", platform: "PostgreSQL", asset: "pg-customer360-prd", access: "SUPERUSER, BYPASSRLS", risk: "Critical", lastUsed: "12 minutes ago", recommendation: "Replace with scoped export role" },
  { id: "ACC-309", principal: "OPS_DBA_LEGACY", principalType: "Database role", platform: "Sybase ASE", asset: "ase-treasury-prd-02", access: "sa_role", risk: "High", lastUsed: "46 days ago", recommendation: "Remove standing administrative access" },
  { id: "ACC-304", principal: "anita.rao", principalType: "Human", platform: "Oracle", asset: "ora-payments-prd-01", access: "SELECT ANY TABLE", risk: "High", lastUsed: "2 hours ago", recommendation: "Replace system privilege with schema role" },
  { id: "ACC-298", principal: "svc_risk_batch", principalType: "Service account", platform: "Oracle", asset: "ora-risk-dwh-uat", access: "CREATE SESSION, RISK_ETL", risk: "Medium", lastUsed: "18 hours ago", recommendation: "Rotate credential and confirm owner" },
  { id: "ACC-291", principal: "mobile_release", principalType: "Database role", platform: "PostgreSQL", asset: "pg-digital-dev-04", access: "CREATE ON SCHEMA public", risk: "Medium", lastUsed: "5 days ago", recommendation: "Move DDL grants to deployment schema" },
] as const;

export const maskingPolicies: readonly MaskingPolicy[] = [
  { id: "MSK-101", name: "Customer direct identifiers", classification: "Restricted PII", technique: "Deterministic tokenization", coverage: 96, datasets: 18, environment: "UAT & Development", status: "Validated", lastValidated: "12 Aug 2026", workflowStatus: "validated" },
  { id: "MSK-102", name: "Payment account details", classification: "PCI data", technique: "Format-preserving encryption", coverage: 100, datasets: 9, environment: "UAT", status: "Validated", lastValidated: "11 Aug 2026", workflowStatus: "validated" },
  { id: "MSK-103", name: "Contact information", classification: "Confidential PII", technique: "Consistent substitution", coverage: 82, datasets: 26, environment: "Development", status: "Pilot", lastValidated: "09 Aug 2026" },
  { id: "MSK-104", name: "Treasury counterparties", classification: "Restricted", technique: "Seeded shuffling", coverage: 44, datasets: 7, environment: "UAT", status: "Pilot", lastValidated: "06 Aug 2026" },
  { id: "MSK-105", name: "Operational telemetry", classification: "Internal", technique: "IP address generalization", coverage: 0, datasets: 4, environment: "Development", status: "Draft", lastValidated: "Not validated" },
] as const;

export const evidenceRecords: readonly EvidenceRecord[] = [
  { id: "EVD-80041", control: "Encryption at rest / ENC-AT-01", asset: "ora-payments-prd-01", platform: "Oracle", source: "V$ENCRYPTED_TABLESPACES", collectedAt: "12 Aug 2026, 09:42:18 IST", integrity: "Digest recorded", retention: "7 years" },
  { id: "EVD-80040", control: "Privileged role inventory / IAM-LP-01", asset: "pg-customer360-prd", platform: "PostgreSQL", source: "pg_roles / pg_auth_members", collectedAt: "12 Aug 2026, 09:18:09 IST", integrity: "Digest recorded", retention: "7 years" },
  { id: "EVD-80039", control: "Audit configuration / LOG-AU-02", asset: "ase-treasury-prd-02", platform: "Sybase ASE", source: "sp_configure metadata", collectedAt: "12 Aug 2026, 08:55:42 IST", integrity: "Digest recorded", retention: "7 years" },
  { id: "EVD-80038", control: "TLS enforcement / ENC-TR-03", asset: "ora-risk-dwh-uat", platform: "Oracle", source: "sqlnet.ora fingerprint", collectedAt: "12 Aug 2026, 07:31:20 IST", integrity: "Digest recorded", retention: "3 years" },
  { id: "EVD-80037", control: "Sensitive-data discovery / DLP-DS-01", asset: "pg-digital-dev-04", platform: "PostgreSQL", source: "Classifier 2.4.1", collectedAt: "11 Aug 2026, 23:40:54 IST", integrity: "Digest recorded", retention: "3 years" },
  { id: "EVD-80036", control: "Encryption at rest / ENC-AT-01", asset: "ase-opsarchive-prd", platform: "Sybase ASE", source: "sysdatabases fingerprint", collectedAt: "11 Aug 2026, 18:12:11 IST", integrity: "Missing digest", retention: "7 years" },
] as const;

export const connectors: readonly Connector[] = [
  { id: "CON-MUM-01", name: "Mumbai Production Collector", platform: "Oracle", version: "2.4.1", region: "Mumbai DC-1", assets: 8, status: "Online", lastHeartbeat: "14 seconds ago", nextScan: "12 Aug, 12:00 IST", serviceAccount: "svc_aegis_oracle_ro", releaseChannel: "Stable" },
  { id: "CON-AWS-02", name: "AWS India Collector", platform: "PostgreSQL", version: "2.4.1", region: "AWS ap-south-1", assets: 14, status: "Online", lastHeartbeat: "8 seconds ago", nextScan: "12 Aug, 12:15 IST", serviceAccount: "svc_aegis_pg_ro", releaseChannel: "Stable" },
  { id: "CON-PUN-01", name: "Pune Legacy Estate", platform: "Sybase ASE", version: "2.3.8", region: "Pune DC-2", assets: 11, status: "Degraded", lastHeartbeat: "4 minutes ago", nextScan: "Retrying in 2 min", serviceAccount: "svc_aegis_ase_ro", releaseChannel: "Controlled" },
  { id: "CON-AZR-01", name: "Azure Engineering Collector", platform: "PostgreSQL", version: "2.4.1", region: "Azure Central India", assets: 6, status: "Online", lastHeartbeat: "21 seconds ago", nextScan: "12 Aug, 13:00 IST", serviceAccount: "svc_aegis_pg_dev_ro", releaseChannel: "Stable" },
] as const;

export const controlDomains: readonly ControlDomain[] = [
  { name: "Database encryption", score: 78, change: 3, controls: 42, findings: 4 },
  { name: "Data protection", score: 86, change: 5, controls: 37, findings: 3 },
  { name: "Access security", score: 69, change: -2, controls: 56, findings: 8 },
  { name: "Data masking", score: 82, change: 7, controls: 31, findings: 2 },
] as const;

export const assuranceTrend = [72, 73, 75, 74, 77, 79, 81, 82] as const;

export const platformSummary = [
  { platform: "Oracle" as const, assets: 12, coverage: 89, openFindings: 5, lastScan: "09:42 IST" },
  { platform: "PostgreSQL" as const, assets: 20, coverage: 77, openFindings: 8, lastScan: "09:18 IST" },
  { platform: "Sybase ASE" as const, assets: 11, coverage: 62, openFindings: 7, lastScan: "08:55 IST" },
] as const;

export const recentActivity = [
  { time: "09:42", title: "Oracle estate assessment completed", detail: "8 assets · 128 controls · no collection errors", tone: "good" },
  { time: "09:18", title: "Critical access finding detected", detail: "pg-customer360-prd · IAM-AU-04", tone: "critical" },
  { time: "08:59", title: "Remediation owner assigned", detail: "FND-2035 assigned to Treasury Technology", tone: "info" },
  { time: "08:55", title: "Sybase collection completed with warnings", detail: "1 asset unreachable · retry policy activated", tone: "warning" },
] as const;

export function platformClass(platform: Platform | "All platforms") {
  if (platform === "Oracle") return "oracle";
  if (platform === "PostgreSQL") return "postgres";
  if (platform === "Sybase ASE") return "sybase";
  if (platform === "MySQL") return "mysql";
  return "all";
}
