import "server-only";

import { getChatGPTUser } from "@/app/chatgpt-auth";

import {
  accessReviews,
  assessments,
  assets,
  assuranceTrend,
  connectors,
  controlDomains,
  evidenceRecords,
  findings,
  maskingPolicies,
  platformSummary,
  recentActivity,
  sensitiveColumns,
  type AccessReview,
  type Assessment,
  type AssessmentCollectionResult,
  type AssessmentObservation,
  type AssessmentReview,
  type AssessmentReviewControl,
  type AssessmentReviewDecision,
  type AssessmentReviewDefinition,
  type Connector,
  type ControlDomain,
  type DatabaseAsset,
  type EvidenceRecord,
  type Finding,
  type MaskingPolicy,
  type Platform,
  type ReviewOutcome,
  type SensitiveColumn,
} from "./data";

declare const __AEGISDB_CONSOLE_DATA_MODE__: "api" | "fixture";
declare const __AEGISDB_ASSURANCE_API_BASE_URL__: string;
declare const __AEGISDB_LOCAL_CONSOLE_AUTH__: boolean;
declare const __AEGISDB_LOCAL_CONSOLE_TENANT_ID__: string;
declare const __AEGISDB_LOCAL_CONSOLE_ROLES__: string;
declare const __AEGISDB_LOCAL_SYNTHETIC_COLLECTION__: boolean;
declare const __AEGISDB_LOCAL_MYSQL_MODE__: boolean;

const API_PREFIX = "/api/v1";
const DEFAULT_PAGE_SIZE = 25;
const MAX_PAGE_SIZE = 100;
const MAX_JOIN_ROWS = 10_000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 8_000;
const TOKEN_BROKER_TIMEOUT_MS = 5_000;
const MAX_BROKER_RESPONSE_BYTES = 32 * 1024;
const MAX_ERROR_RESPONSE_BYTES = 64 * 1024;

export type ConsoleDataMode = "api" | "fixture";
export type ConsoleDataSource = "live-api" | "development-fixture";

export interface RepositoryMeta {
  source: ConsoleDataSource;
  fetchedAt: string;
  stale: boolean;
  requestId?: string;
}

export interface RepositoryValue<T> {
  value: T;
  meta: RepositoryMeta;
}

export interface RepositoryPage<T> {
  items: readonly T[];
  nextCursor: string | null;
  limit: number;
}

export interface PageRequest {
  cursor?: string;
  limit?: number;
}

export interface EvidencePageRequest extends PageRequest {
  assessmentId?: string;
  controlId?: string;
}

export interface PlatformSummaryRow {
  platform: Platform;
  assets: number;
  coverage: number;
  scoreAvailable?: boolean;
  openFindings: number;
  lastScan: string;
}

export interface ActivityRow {
  time: string;
  title: string;
  detail: string;
  tone: "good" | "critical" | "info" | "warning";
}

export interface OverviewData {
  assuranceTrend: readonly number[];
  controlDomains: readonly ControlDomain[];
  platformSummary: readonly PlatformSummaryRow[];
  recentActivity: readonly ActivityRow[];
  totals: {
    assets: number;
    connectors: number;
    openFindings: number;
    assessments: number;
    maskingPolicies: number;
    accessReviews: number;
  };
}

export interface AssetCreateInput {
  externalId: string;
  name: string;
  platform: "oracle" | "postgresql" | "sybase" | "mysql";
  version: string;
  edition?: string;
  environment: "production" | "staging" | "test" | "development" | "disaster_recovery";
  owner: string;
  criticality: "critical" | "high" | "medium" | "low";
}

export interface AssessmentStartInput {
  assetId: string;
  connectorId: string;
  controlPackVersionId: string;
}

export interface AssessmentStartResult {
  assessmentId: string;
  jobId: string;
}

export interface ControlDecisionInput {
  assessmentId: string;
  controlDefinitionId: string;
  outcome: ReviewOutcome;
  rationale: string;
}

export interface FindingUpdateInput {
  findingId: string;
  status: "open" | "in_progress" | "resolved";
  owner?: string;
  dueAt?: string;
  reason: string;
}

export interface AccessReviewUpdateInput {
  reviewId: string;
  status: "approved" | "remediation_required" | "closed";
  reason: string;
}

export interface MaskingPolicyCreateInput {
  name: string;
  classification: string;
  strategy: "redact" | "tokenize" | "hash" | "substitute" | "shuffle" | "format_preserving";
  targetEnvironment: "development" | "test" | "staging";
}

export interface MaskingPolicyTransitionInput {
  policyId: string;
  action: "approve" | "record_execution" | "validate" | "archive";
  note: string;
  reference?: string;
}

export interface MaskingCopyStartResult {
  jobId: string;
  status: "pending" | "leased" | "running" | "succeeded" | "failed";
}

export interface ControlPackOption {
  id: string;
  title: string;
  version: string;
  platform: Platform;
  status: "active" | "draft" | "retired";
}

export interface AssessmentTargetOption {
  id: string;
  assetName: string;
  connectorName: string;
  controlPackTitle: string;
  controlPackVersion: string;
  platform: Platform;
}

export interface AssessmentActionOptions {
  assets: readonly DatabaseAsset[];
  connectors: readonly Connector[];
  controlPacks: readonly ControlPackOption[];
  targets: readonly AssessmentTargetOption[];
}

export type ConsoleLoadState<T> =
  | { status: "ready"; result: RepositoryValue<T> }
  | {
      status: "error";
      code: ConsoleRepositoryErrorCode;
      message: string;
      retryable: boolean;
      requestId?: string;
    };

export type ConsoleRepositoryErrorCode =
  | "configuration"
  | "authentication"
  | "authorization"
  | "unavailable"
  | "invalid_response"
  | "unsupported"
  | "validation"
  | "conflict";

export class ConsoleRepositoryError extends Error {
  constructor(
    readonly code: ConsoleRepositoryErrorCode,
    message: string,
    readonly retryable = false,
    readonly requestId?: string,
  ) {
    super(message);
    this.name = "ConsoleRepositoryError";
  }
}

export interface ConsoleRepository {
  getAssets(request?: PageRequest): Promise<RepositoryValue<RepositoryPage<DatabaseAsset>>>;
  getAssessments(request?: PageRequest): Promise<RepositoryValue<RepositoryPage<Assessment>>>;
  getAssessmentReview(assessmentId: string): Promise<RepositoryValue<AssessmentReview>>;
  getFindings(request?: PageRequest & { status?: string }): Promise<RepositoryValue<RepositoryPage<Finding>>>;
  getSensitiveColumns(request?: PageRequest): Promise<RepositoryValue<RepositoryPage<SensitiveColumn>>>;
  getAccessReviews(request?: PageRequest): Promise<RepositoryValue<RepositoryPage<AccessReview>>>;
  getMaskingPolicies(request?: PageRequest): Promise<RepositoryValue<RepositoryPage<MaskingPolicy>>>;
  getEvidenceRecords(request?: EvidencePageRequest): Promise<RepositoryValue<RepositoryPage<EvidenceRecord>>>;
  getConnectors(request?: PageRequest): Promise<RepositoryValue<RepositoryPage<Connector>>>;
  getControlPacks(request?: PageRequest): Promise<RepositoryValue<RepositoryPage<ControlPackOption>>>;
  getAssessmentActionOptions(): Promise<RepositoryValue<AssessmentActionOptions>>;
  getOverview(): Promise<RepositoryValue<OverviewData>>;
  createAsset(input: AssetCreateInput, idempotencyKey: string): Promise<RepositoryValue<DatabaseAsset>>;
  startAssessmentTarget(targetId: string, idempotencyKey: string): Promise<RepositoryValue<AssessmentStartResult>>;
  saveControlDecision(input: ControlDecisionInput, idempotencyKey: string): Promise<RepositoryValue<AssessmentReview>>;
  finalizeAssessment(assessmentId: string, idempotencyKey: string): Promise<RepositoryValue<AssessmentReview>>;
  updateFinding(input: FindingUpdateInput, idempotencyKey: string): Promise<RepositoryValue<Finding>>;
  updateAccessReview(input: AccessReviewUpdateInput, idempotencyKey: string): Promise<RepositoryValue<AccessReview>>;
  createMaskingPolicy(input: MaskingPolicyCreateInput, idempotencyKey: string): Promise<RepositoryValue<MaskingPolicy>>;
  transitionMaskingPolicy(input: MaskingPolicyTransitionInput, idempotencyKey: string): Promise<RepositoryValue<MaskingPolicy>>;
  queueMaskingCopy(policyId: string, idempotencyKey: string): Promise<RepositoryValue<MaskingCopyStartResult>>;
}

export function getConsoleDataMode(): ConsoleDataMode {
  return __AEGISDB_CONSOLE_DATA_MODE__;
}

export function getLocalSyntheticCollectionMode(): boolean {
  return __AEGISDB_LOCAL_SYNTHETIC_COLLECTION__;
}

export function getLocalMySqlMode(): boolean {
  return __AEGISDB_LOCAL_MYSQL_MODE__;
}

export function getConsoleRepository(): ConsoleRepository {
  return getConsoleDataMode() === "fixture" ? fixtureRepository : apiRepository;
}

export async function loadConsoleData<T>(operation: () => Promise<RepositoryValue<T>>): Promise<ConsoleLoadState<T>> {
  try {
    return { status: "ready", result: await operation() };
  } catch (error) {
    if (error instanceof ConsoleRepositoryError) {
      return {
        status: "error",
        code: error.code,
        message: error.message,
        retryable: error.retryable,
        requestId: error.requestId,
      };
    }
    return {
      status: "error",
      code: "unavailable",
      message: "The assurance control plane could not be reached.",
      retryable: true,
    };
  }
}

class FixtureConsoleRepository implements ConsoleRepository {
  async getAssets(request?: PageRequest) { return fixturePage(assets, request); }
  async getAssessments(request?: PageRequest) { return fixturePage(assessments, request); }
  async getAssessmentReview(): Promise<RepositoryValue<AssessmentReview>> { throw demoReadOnly(); }
  async getFindings(request?: PageRequest & { status?: string }) { return fixturePage(findings, request); }
  async getSensitiveColumns(request?: PageRequest) { return fixturePage(sensitiveColumns, request); }
  async getAccessReviews(request?: PageRequest) { return fixturePage(accessReviews, request); }
  async getMaskingPolicies(request?: PageRequest) { return fixturePage(maskingPolicies, request); }
  async getEvidenceRecords(request?: EvidencePageRequest) {
    const filtered = evidenceRecords.filter((item) =>
      (!request?.assessmentId || item.assessmentId === request.assessmentId) &&
      (!request?.controlId || item.control === request.controlId)
    );
    return fixturePage(filtered, request);
  }
  async getConnectors(request?: PageRequest) { return fixturePage(connectors, request); }
  async getControlPacks(request?: PageRequest) { return fixturePage<ControlPackOption>([], request); }
  async getAssessmentActionOptions(): Promise<RepositoryValue<AssessmentActionOptions>> {
    return fixtureValue({ assets, connectors, controlPacks: [], targets: [] });
  }
  async getOverview(): Promise<RepositoryValue<OverviewData>> {
    return fixtureValue({
      assuranceTrend,
      controlDomains,
      platformSummary,
      recentActivity,
      totals: {
        assets: 43,
        connectors: 4,
        openFindings: 20,
        assessments: 166,
        maskingPolicies: 5,
        accessReviews: 39,
      },
    });
  }
  async createAsset(): Promise<RepositoryValue<DatabaseAsset>> { throw demoReadOnly(); }
  async startAssessmentTarget(): Promise<RepositoryValue<AssessmentStartResult>> { throw demoReadOnly(); }
  async saveControlDecision(): Promise<RepositoryValue<AssessmentReview>> { throw demoReadOnly(); }
  async finalizeAssessment(): Promise<RepositoryValue<AssessmentReview>> { throw demoReadOnly(); }
  async updateFinding(): Promise<RepositoryValue<Finding>> { throw demoReadOnly(); }
  async updateAccessReview(): Promise<RepositoryValue<AccessReview>> { throw demoReadOnly(); }
  async createMaskingPolicy(): Promise<RepositoryValue<MaskingPolicy>> { throw demoReadOnly(); }
  async transitionMaskingPolicy(): Promise<RepositoryValue<MaskingPolicy>> { throw demoReadOnly(); }
  async queueMaskingCopy(): Promise<RepositoryValue<MaskingCopyStartResult>> { throw demoReadOnly(); }
}

class ApiConsoleRepository implements ConsoleRepository {
  async getAssets(request?: PageRequest): Promise<RepositoryValue<RepositoryPage<DatabaseAsset>>> {
    const page = await apiPage("/assets", request);
    return mapPage(page, mapAsset);
  }

  async getAssessments(request?: PageRequest): Promise<RepositoryValue<RepositoryPage<Assessment>>> {
    const page = await apiPage("/assessments", request);
    const assetData = await apiAssetMap(page.value.items);
    const mapped = mapPage(page, (item) => mapAssessment(item, assetData.value));
    return { ...mapped, meta: mergeMeta(mapped.meta, assetData.meta) };
  }

  async getAssessmentReview(assessmentId: string): Promise<RepositoryValue<AssessmentReview>> {
    const id = resourceId(assessmentId);
    return hydrateAssessmentReview(
      await apiObject(`/assessments/${encodeURIComponent(id)}/review`),
    );
  }

  async getFindings(request?: PageRequest & { status?: string }): Promise<RepositoryValue<RepositoryPage<Finding>>> {
    const query = request?.status && request.status !== "all" ? { status: apiFindingStatus(request.status) } : undefined;
    const page = await apiPage("/findings", request, query);
    const assetData = await apiAssetMap(page.value.items);
    const mapped = mapPage(page, (item) => mapFinding(item, assetData.value));
    return { ...mapped, meta: mergeMeta(mapped.meta, assetData.meta) };
  }

  async getSensitiveColumns(request?: PageRequest): Promise<RepositoryValue<RepositoryPage<SensitiveColumn>>> {
    return mapPage(await apiPage("/sensitive-columns", request), mapSensitiveColumn);
  }

  async getAccessReviews(request?: PageRequest): Promise<RepositoryValue<RepositoryPage<AccessReview>>> {
    const page = await apiPage("/access-reviews", request);
    const assetData = await apiAssetMap(page.value.items);
    const mapped = mapPage(page, (item) => mapAccessReview(item, assetData.value));
    return { ...mapped, meta: mergeMeta(mapped.meta, assetData.meta) };
  }

  async getMaskingPolicies(request?: PageRequest): Promise<RepositoryValue<RepositoryPage<MaskingPolicy>>> {
    return mapPage(await apiPage("/masking-policies", request), mapMaskingPolicy);
  }

  async getEvidenceRecords(request?: EvidencePageRequest): Promise<RepositoryValue<RepositoryPage<EvidenceRecord>>> {
    const [page, assessmentsPage, assetsPage] = await Promise.all([
      apiPage("/evidence", request, {
        assessment_id: request?.assessmentId,
        control_id: request?.controlId,
      }),
      apiAllPages("/assessments"),
      apiAllPages("/assets"),
    ]);
    const assessmentsById = new Map(assessmentsPage.value.items.map((item) => [requiredString(item, "id"), item]));
    const assetsById = new Map(assetsPage.value.items.map((item) => [requiredString(item, "id"), item]));
    return mapPage(page, (item) => mapEvidence(item, assessmentsById, assetsById));
  }

  async getConnectors(request?: PageRequest): Promise<RepositoryValue<RepositoryPage<Connector>>> {
    const page = await apiPage("/connectors", request);
    const assetData = await apiAssetMap(page.value.items);
    const mapped = mapPage(page, (item) => mapConnector(item, assetData.value));
    return { ...mapped, meta: mergeMeta(mapped.meta, assetData.meta) };
  }

  async getControlPacks(request?: PageRequest): Promise<RepositoryValue<RepositoryPage<ControlPackOption>>> {
    return mapPage(await apiPage("/control-pack-versions", request), mapControlPack);
  }

  async getAssessmentActionOptions(): Promise<RepositoryValue<AssessmentActionOptions>> {
    const [assetsPage, connectorsPage, controlPacksPage] = await Promise.all([
      apiAllPages("/assets"),
      apiAllPages("/connectors"),
      apiAllPages("/control-pack-versions"),
    ]);
    const assetsById = new Map(
      assetsPage.value.items.map((asset) => [requiredString(asset, "id"), asset]),
    );
    const meta = mergeMeta(assetsPage.meta, connectorsPage.meta, controlPacksPage.meta);
    const actionOptions = {
      assets: assetsPage.value.items.map(mapAsset),
      connectors: connectorsPage.value.items.map((connector) =>
        mapConnector(connector, assetsById),
      ),
      controlPacks: controlPacksPage.value.items.map(mapControlPack),
    };
    return {
      value: {
        ...actionOptions,
        targets: buildAssessmentTargets(actionOptions, meta.requestId),
      },
      meta,
    };
  }

  async getOverview(): Promise<RepositoryValue<OverviewData>> {
    const [summary, assetsPage, findingsPage, assessmentsPage] = await Promise.all([
      apiObject("/dashboard/summary"),
      apiAllPages("/assets"),
      apiAllPages("/findings"),
      apiAllPages("/assessments"),
    ]);
    const liveAssets = assetsPage.value.items.map(mapAsset);
    const rawFindings = findingsPage.value.items;
    const rawAssessments = assessmentsPage.value.items;
    const currentAssessments = latestCompletedAssessments(rawAssessments);
    const platformRows = (["Oracle", "PostgreSQL", "Sybase ASE", "MySQL"] as const).map((platform) => {
      const platformAssets = liveAssets.filter((asset) => asset.platform === platform);
      const assetIds = new Set(platformAssets.map((asset) => asset.id));
      const platformFindings = rawFindings.filter((item) => assetIds.has(requiredString(item, "asset_id")));
      const completedScores = currentAssessments
        .filter((item) => assetIds.has(requiredString(item, "asset_id")))
        .map((item) => optionalNumber(item, "score"))
        .filter((score): score is number => score !== null);
      return {
        platform,
        assets: platformAssets.length,
        coverage: completedScores.length ? Math.round(completedScores.reduce((sum, score) => sum + score, 0) / completedScores.length) : 0,
        scoreAvailable: completedScores.length > 0,
        openFindings: platformFindings.filter((item) => !["resolved", "false_positive"].includes(requiredString(item, "status"))).length,
        lastScan: newestTimestamp(rawAssessments.filter((item) => assetIds.has(requiredString(item, "asset_id")))),
      };
    });
    const scores = rawAssessments
      .filter((item) => requiredString(item, "status") === "completed")
      .sort(compareAssessmentTime)
      .map((item) => optionalNumber(item, "score"))
      .filter((score): score is number => score !== null)
      .slice(-8);
    const result: OverviewData = {
      assuranceTrend: scores,
      controlDomains: deriveControlDomains(currentAssessments, rawFindings),
      platformSummary: platformRows,
      recentActivity: deriveActivity(rawAssessments, rawFindings),
      totals: {
        assets: requiredNumber(summary.value, "assets"),
        connectors: requiredNumber(summary.value, "connectors"),
        openFindings: requiredNumber(summary.value, "open_findings"),
        assessments: requiredNumber(summary.value, "assessments"),
        maskingPolicies: requiredNumber(summary.value, "masking_policies"),
        accessReviews: requiredNumber(summary.value, "access_reviews"),
      },
    };
    return { value: result, meta: mergeMeta(summary.meta, assetsPage.meta, findingsPage.meta, assessmentsPage.meta) };
  }

  async createAsset(input: AssetCreateInput, idempotencyKey: string): Promise<RepositoryValue<DatabaseAsset>> {
    const response = await apiMutation("/assets", {
      external_id: input.externalId,
      name: input.name,
      platform: input.platform,
      version: input.version,
      edition: input.edition || null,
      environment: input.environment,
      owner: input.owner,
      criticality: input.criticality,
      tags: {},
    }, idempotencyKey);
    return { value: mapAsset(response.value), meta: response.meta };
  }

  async startAssessmentTarget(targetId: string, idempotencyKey: string): Promise<RepositoryValue<AssessmentStartResult>> {
    // The rendered value is only a convenience. Resolve it against a fresh,
    // tenant-scoped snapshot so a forged or stale browser value cannot select
    // an unrelated asset, connector, or control pack.
    const options = await this.getAssessmentActionOptions();
    const target = options.value.targets.find((candidate) => candidate.id === targetId);
    if (!target) {
      throw new ConsoleRepositoryError(
        "validation",
        "The selected assessment target is no longer available.",
      );
    }
    const [assetId, connectorId, controlPackVersionId] = target.id.split(":");
    return this.startAssessment(
      { assetId, connectorId, controlPackVersionId },
      idempotencyKey,
    );
  }

  async saveControlDecision(
    input: ControlDecisionInput,
    idempotencyKey: string,
  ): Promise<RepositoryValue<AssessmentReview>> {
    const assessmentId = resourceId(input.assessmentId);
    const definitionId = resourceId(input.controlDefinitionId);
    const response = await apiMutation(
      `/assessments/${encodeURIComponent(assessmentId)}/control-decisions/${encodeURIComponent(definitionId)}`,
      { outcome: input.outcome, rationale: input.rationale },
      idempotencyKey,
      "PUT",
    );
    return hydrateAssessmentReview(response);
  }

  async finalizeAssessment(
    assessmentId: string,
    idempotencyKey: string,
  ): Promise<RepositoryValue<AssessmentReview>> {
    const id = resourceId(assessmentId);
    const response = await apiMutation(
      `/assessments/${encodeURIComponent(id)}/finalize`,
      { confirmation: "finalize" },
      idempotencyKey,
    );
    return hydrateAssessmentReview(response);
  }

  private async startAssessment(input: AssessmentStartInput, idempotencyKey: string): Promise<RepositoryValue<AssessmentStartResult>> {
    const run = await apiMutation("/assessment-runs", {
      asset_id: input.assetId,
      connector_id: input.connectorId,
      control_pack_version_id: input.controlPackVersionId,
      run_key: idempotencyKey,
      max_attempts: 5,
    }, idempotencyKey);
    const assessment = asRecord(run.value.assessment);
    const job = asRecord(run.value.job);
    const assessmentId = requiredString(assessment, "id");
    if (requiredString(job, "assessment_id") !== assessmentId) throw invalidResponse(run.meta.requestId);
    return {
      value: { assessmentId, jobId: requiredString(job, "id") },
      meta: run.meta,
    };
  }

  async updateFinding(input: FindingUpdateInput, idempotencyKey: string): Promise<RepositoryValue<Finding>> {
    const response = await apiMutation(`/findings/${encodeURIComponent(input.findingId)}`, {
      status: input.status,
      owner: input.owner || null,
      due_at: input.dueAt || null,
      reason: input.reason,
    }, idempotencyKey, "PATCH");
    const asset = await apiObject(`/assets/${encodeURIComponent(requiredString(response.value, "asset_id"))}`);
    return { value: mapFinding(response.value, new Map([[requiredString(asset.value, "id"), asset.value]])), meta: mergeMeta(asset.meta, response.meta) };
  }

  async updateAccessReview(input: AccessReviewUpdateInput, idempotencyKey: string): Promise<RepositoryValue<AccessReview>> {
    const response = await apiMutation(`/access-reviews/${encodeURIComponent(input.reviewId)}`, {
      status: input.status,
      decision_summary: { source: "console_review" },
      reason: input.reason,
    }, idempotencyKey, "PATCH");
    const asset = await apiObject(`/assets/${encodeURIComponent(requiredString(response.value, "asset_id"))}`);
    return {
      value: mapAccessReview(response.value, new Map([[requiredString(asset.value, "id"), asset.value]])),
      meta: mergeMeta(response.meta, asset.meta),
    };
  }

  async createMaskingPolicy(input: MaskingPolicyCreateInput, idempotencyKey: string): Promise<RepositoryValue<MaskingPolicy>> {
    const response = await apiMutation("/masking-policies", {
      name: input.name,
      version: 1,
      classification: input.classification,
      strategy: input.strategy,
      target_environment: input.targetEnvironment,
      parameters: {},
    }, idempotencyKey);
    return { value: mapMaskingPolicy(response.value), meta: response.meta };
  }

  async transitionMaskingPolicy(input: MaskingPolicyTransitionInput, idempotencyKey: string): Promise<RepositoryValue<MaskingPolicy>> {
    const response = await apiMutation(`/masking-policies/${encodeURIComponent(input.policyId)}/workflow`, {
      action: input.action,
      note: input.note,
      reference: input.reference || null,
    }, idempotencyKey, "PATCH");
    return { value: mapMaskingPolicy(response.value), meta: response.meta };
  }

  async queueMaskingCopy(policyId: string, idempotencyKey: string): Promise<RepositoryValue<MaskingCopyStartResult>> {
    const id = resourceId(policyId);
    const response = await apiMutation(
      `/masking-policies/${encodeURIComponent(id)}/copy-runs`,
      {},
      idempotencyKey,
    );
    if (requiredString(response.value, "job_type") !== "masking_copy") {
      throw invalidResponse(response.meta.requestId);
    }
    const status = requiredString(response.value, "status");
    if (!["pending", "leased", "running", "succeeded", "failed"].includes(status)) {
      throw invalidResponse(response.meta.requestId);
    }
    return {
      value: {
        jobId: requiredString(response.value, "id"),
        status: status as MaskingCopyStartResult["status"],
      },
      meta: response.meta,
    };
  }
}

const fixtureRepository = new FixtureConsoleRepository();
const apiRepository = new ApiConsoleRepository();

function fixtureValue<T>(value: T): RepositoryValue<T> {
  return { value, meta: { source: "development-fixture", fetchedAt: new Date().toISOString(), stale: false } };
}

function fixturePage<T>(items: readonly T[], request?: PageRequest): RepositoryValue<RepositoryPage<T>> {
  const limit = normalizeLimit(request?.limit);
  const start = fixtureOffset(request?.cursor);
  return fixtureValue({
    items: items.slice(start, start + limit),
    nextCursor: start + limit < items.length ? `fixture-${start + limit}` : null,
    limit,
  });
}

function fixtureOffset(cursor?: string): number {
  if (!cursor) return 0;
  const match = /^fixture-(\d{1,6})$/.exec(cursor);
  return match ? Number(match[1]) : 0;
}

function demoReadOnly(): ConsoleRepositoryError {
  return new ConsoleRepositoryError("unsupported", "Write actions are disabled while local demonstration fixtures are active.");
}

async function apiPage(
  path: string,
  request?: PageRequest,
  filters?: Record<string, string | undefined>,
): Promise<RepositoryValue<{ items: Record<string, unknown>[]; nextCursor: string | null; limit: number }>> {
  const params = new URLSearchParams();
  const limit = normalizeLimit(request?.limit);
  params.set("limit", String(limit));
  const cursor = normalizeCursor(request?.cursor);
  if (cursor) params.set("cursor", cursor);
  for (const [key, value] of Object.entries(filters ?? {})) if (value) params.set(key, value);
  const response = await apiRequest(`${path}?${params.toString()}`, { method: "GET" });
  const body = asRecord(response.value);
  const items = body.items;
  if (!Array.isArray(items)) throw invalidResponse(response.meta.requestId);
  const parsed = items.map(asRecord);
  const nextCursor = body.next_cursor;
  if (nextCursor !== null && nextCursor !== undefined && typeof nextCursor !== "string") throw invalidResponse(response.meta.requestId);
  return {
    value: { items: parsed, nextCursor: nextCursor ?? null, limit: requiredNumber(body, "limit") },
    meta: response.meta,
  };
}

async function apiAllPages(
  path: string,
  filters?: Record<string, string | undefined>,
): Promise<RepositoryValue<{ items: Record<string, unknown>[] }>> {
  const items: Record<string, unknown>[] = [];
  const seenCursors = new Set<string>();
  const metadata: RepositoryMeta[] = [];
  let cursor: string | undefined;
  while (true) {
    const page = await apiPage(path, { cursor, limit: MAX_PAGE_SIZE }, filters);
    metadata.push(page.meta);
    items.push(...page.value.items);
    const next = page.value.nextCursor;
    if (items.length > MAX_JOIN_ROWS) {
      throw boundedViewError(page.meta.requestId);
    }
    if (!next) break;
    if (items.length >= MAX_JOIN_ROWS || seenCursors.has(next)) {
      throw boundedViewError(page.meta.requestId);
    }
    seenCursors.add(next);
    cursor = next;
  }
  return { value: { items }, meta: metadata.length ? mergeMeta(...metadata) : liveMeta() };
}

async function apiObject(path: string): Promise<RepositoryValue<Record<string, unknown>>> {
  const response = await apiRequest(path, { method: "GET" });
  return { value: asRecord(response.value), meta: response.meta };
}

async function hydrateAssessmentReview(
  review: RepositoryValue<Record<string, unknown>>,
): Promise<RepositoryValue<AssessmentReview>> {
  const assessment = asRecord(review.value.assessment);
  const asset = await apiObject(
    `/assets/${encodeURIComponent(requiredString(assessment, "asset_id"))}`,
  );
  const assetId = requiredString(asset.value, "id");
  return {
    value: mapAssessmentReview(
      review.value,
      new Map([[assetId, asset.value]]),
    ),
    meta: mergeMeta(review.meta, asset.meta),
  };
}

async function apiAssetMap(rows: readonly Record<string, unknown>[]): Promise<RepositoryValue<Map<string, Record<string, unknown>>>> {
  const ids = [...new Set(rows.map((row) => requiredString(row, "asset_id")))];
  const loaded = await Promise.all(ids.map((id) => apiObject(`/assets/${encodeURIComponent(id)}`)));
  return {
    value: new Map(loaded.map((asset) => [requiredString(asset.value, "id"), asset.value])),
    meta: loaded.length ? mergeMeta(...loaded.map((asset) => asset.meta)) : liveMeta(),
  };
}

async function apiMutation(path: string, body: Record<string, unknown>, idempotencyKey: string, method: "POST" | "PUT" | "PATCH" = "POST"): Promise<RepositoryValue<Record<string, unknown>>> {
  if (!/^[A-Za-z0-9._:-]{8,128}$/.test(idempotencyKey)) {
    throw new ConsoleRepositoryError("validation", "The operation identifier is invalid.");
  }
  const response = await apiRequest(path, { method, body, idempotencyKey });
  return { value: asRecord(response.value), meta: response.meta };
}

async function apiRequest(
  path: string,
  options: { method: "GET" | "POST" | "PUT" | "PATCH"; body?: Record<string, unknown>; idempotencyKey?: string },
): Promise<RepositoryValue<unknown>> {
  const config = await apiConfig();
  const requestId = crypto.randomUUID();
  // A mutation is retried only after a transport failure and always with the
  // same server-generated idempotency key. HTTP failures are never retried.
  const attempts = options.method === "GET" ? 3 : options.idempotencyKey ? 2 : 1;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch(new URL(`${API_PREFIX}${path}`, config.baseUrl), {
        method: options.method,
        cache: "no-store",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          accept: "application/json",
          ...config.authHeaders,
          "x-request-id": requestId,
          ...(options.body ? { "content-type": "application/json" } : {}),
          ...(options.idempotencyKey ? { "idempotency-key": options.idempotencyKey } : {}),
        },
        body: options.body ? JSON.stringify(options.body) : undefined,
      });
      const responseRequestId = response.headers.get("x-request-id") ?? requestId;
      if (response.status >= 300 && response.status < 400) {
        throw new ConsoleRepositoryError(
          "unavailable",
          "The assurance control plane returned an unsafe redirect.",
          false,
          responseRequestId,
        );
      }
      if (!response.ok) {
        if (options.method === "GET" && [502, 503, 504].includes(response.status) && attempt < attempts) {
          await boundedBackoff(attempt);
          continue;
        }
        throw await responseError(response, responseRequestId);
      }
      if (!isJsonResponse(response)) throw invalidResponse(responseRequestId);
      const text = await readBoundedResponseBody(
        response,
        MAX_RESPONSE_BYTES,
        () => invalidResponse(responseRequestId),
      );
      let value: unknown;
      try { value = JSON.parse(text); } catch { throw invalidResponse(responseRequestId); }
      return {
        value,
        meta: {
          source: "live-api",
          fetchedAt: new Date().toISOString(),
          stale: response.headers.get("x-data-stale") === "true" || /\b110\b/.test(response.headers.get("warning") ?? ""),
          requestId: responseRequestId,
        },
      };
    } catch (error) {
      if (error instanceof ConsoleRepositoryError) throw error;
      if (attempt < attempts) {
        await boundedBackoff(attempt);
        continue;
      }
      logTransportFailure(error, requestId, options.method, attempt);
      throw new ConsoleRepositoryError("unavailable", "The assurance control plane is temporarily unavailable.", true, requestId);
    } finally {
      clearTimeout(timer);
    }
  }
  throw new ConsoleRepositoryError("unavailable", "The assurance control plane is temporarily unavailable.", true, requestId);
}

function logTransportFailure(
  error: unknown,
  requestId: string,
  method: "GET" | "POST" | "PUT" | "PATCH",
  attempt: number,
): void {
  const cause = error instanceof Error ? error.cause : undefined;
  const causeCode =
    typeof cause === "object" && cause !== null && "code" in cause &&
    typeof cause.code === "string"
      ? cause.code.slice(0, 64)
      : undefined;
  const errorMessage =
    error instanceof Error ? safeTransportDiagnostic(error.message) : undefined;
  const causeMessage =
    typeof cause === "object" && cause !== null && "message" in cause &&
    typeof cause.message === "string"
      ? safeTransportDiagnostic(cause.message)
      : undefined;
  console.error(
    JSON.stringify({
      timestamp: new Date().toISOString(),
      level: "error",
      event: "console.api.transport_failure",
      request_id: requestId,
      method,
      attempt,
      error_name: error instanceof Error ? error.name.slice(0, 64) : "UnknownError",
      ...(causeCode ? { cause_code: causeCode } : {}),
      ...(errorMessage ? { error_message: errorMessage } : {}),
      ...(causeMessage ? { cause_message: causeMessage } : {}),
    }),
  );
}

function safeTransportDiagnostic(value: string): string | undefined {
  const normalized = value
    .replace(/https?:\/\/[^\s]+/gi, "[redacted-origin]")
    .replace(/[\r\n\0]/g, " ")
    .trim();
  return normalized ? normalized.slice(0, 160) : undefined;
}

async function apiConfig(): Promise<{ baseUrl: URL; authHeaders: Record<string, string> }> {
  if (getConsoleDataMode() !== "api") throw demoReadOnly();
  const configured = __AEGISDB_ASSURANCE_API_BASE_URL__;
  if (!configured) throw new ConsoleRepositoryError("configuration", "A live assurance API connection has not been configured.");
  let baseUrl: URL;
  try { baseUrl = new URL(configured); } catch { throw new ConsoleRepositoryError("configuration", "The assurance API configuration is invalid."); }
  const isLocal = ["localhost", "127.0.0.1", "::1"].includes(baseUrl.hostname);
  if (
    baseUrl.username || baseUrl.password || baseUrl.search || baseUrl.hash ||
    (baseUrl.protocol !== "https:" && !(isLocal && __AEGISDB_LOCAL_CONSOLE_AUTH__)) ||
    (baseUrl.pathname !== "/" && baseUrl.pathname !== "")
  ) {
    throw new ConsoleRepositoryError("configuration", "The assurance API configuration is invalid.");
  }
  if (isLocal && __AEGISDB_LOCAL_CONSOLE_AUTH__) {
    const tenant = safeDevelopmentIdentity(
      __AEGISDB_LOCAL_CONSOLE_TENANT_ID__,
      "local-development",
    );
    const roles = safeDevelopmentIdentity(
      __AEGISDB_LOCAL_CONSOLE_ROLES__,
      "admin,security_analyst,database_owner",
    );
    return {
      baseUrl,
      authHeaders: {
        "x-tenant-id": tenant,
        "x-subject": "local-development-user",
        "x-roles": roles,
      },
    };
  }

  const user = await getChatGPTUser();
  if (!user) throw new ConsoleRepositoryError("authentication", "A signed-in Sites user is required.");
  const token = await exchangeUserToken(user);
  return { baseUrl, authHeaders: { authorization: `Bearer ${token}` } };
}

interface BrokerToken {
  token: string;
  expiresAt: number;
}

const brokerTokenCache = new Map<string, BrokerToken>();

async function exchangeUserToken(user: { userId: string; email: string }): Promise<string> {
  const cached = brokerTokenCache.get(user.userId);
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (cached && cached.expiresAt - 30 > nowSeconds) return cached.token;

  const brokerUrl = secureRuntimeUrl(process.env.AEGISDB_TOKEN_BROKER_URL, "token broker");
  const clientId = safeRuntimeSecret(process.env.AEGISDB_TOKEN_BROKER_CLIENT_ID, "token broker client ID", 256);
  if (clientId.includes(":")) throw new ConsoleRepositoryError("configuration", "The token broker client ID configuration is invalid.");
  const clientSecret = safeRuntimeSecret(process.env.AEGISDB_TOKEN_BROKER_CLIENT_SECRET, "token broker client secret", 4_096);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TOKEN_BROKER_TIMEOUT_MS);
  let response: Response;
  let text: string;
  try {
    response = await fetch(brokerUrl, {
      method: "POST",
      cache: "no-store",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        authorization: `Basic ${encodeBasicCredentials(clientId, clientSecret)}`,
        "x-request-id": crypto.randomUUID(),
      },
      body: JSON.stringify({
        grant_type: "urn:aegisdb:params:oauth:grant-type:sites-user",
        user_id: user.userId,
        user_email: user.email,
        audience: "database-security-assurance-api",
      }),
    });
    if (response.status >= 300 && response.status < 400) {
      await cancelResponseBody(response);
      throw new ConsoleRepositoryError("authentication", "Per-user API authorization returned an unsafe redirect.");
    }
    text = await readBoundedResponseBody(
      response,
      MAX_BROKER_RESPONSE_BYTES,
      () => new ConsoleRepositoryError(
        "authentication",
        "The token broker returned an invalid response.",
        response.status >= 500,
      ),
    );
  } catch (error) {
    if (error instanceof ConsoleRepositoryError) throw error;
    throw new ConsoleRepositoryError("authentication", "Per-user API authorization is temporarily unavailable.", true);
  } finally {
    clearTimeout(timer);
  }
  if (!response.ok || !isJsonResponse(response)) {
    throw new ConsoleRepositoryError("authentication", "Per-user API authorization was rejected.", response.status >= 500);
  }
  let body: Record<string, unknown>;
  try { body = asRecord(JSON.parse(text)); } catch { throw new ConsoleRepositoryError("authentication", "The token broker returned an invalid response."); }
  const token = requiredBrokerString(body, "access_token", 8_192);
  const tokenType = requiredBrokerString(body, "token_type", 32);
  const expiresIn = body.expires_in;
  if (tokenType.toLowerCase() !== "bearer" || typeof expiresIn !== "number" || !Number.isInteger(expiresIn) || expiresIn < 60 || expiresIn > 3_600) {
    throw new ConsoleRepositoryError("authentication", "The token broker returned an invalid response.");
  }
  const expiresAt = nowSeconds + expiresIn;
  brokerTokenCache.set(user.userId, { token, expiresAt });
  pruneTokenCache(nowSeconds);
  return token;
}

function secureRuntimeUrl(value: string | undefined, label: string): URL {
  if (!value) throw new ConsoleRepositoryError("configuration", `The ${label} is not configured.`);
  let url: URL;
  try { url = new URL(value); } catch { throw new ConsoleRepositoryError("configuration", `The ${label} configuration is invalid.`); }
  if (url.protocol !== "https:" || !url.hostname || url.username || url.password || url.search || url.hash) {
    throw new ConsoleRepositoryError("configuration", `The ${label} configuration is invalid.`);
  }
  return url;
}

function safeRuntimeSecret(value: string | undefined, label: string, maximum: number): string {
  const normalized = value?.trim() ?? "";
  if (!normalized || normalized.length > maximum || /[\r\n\0]/.test(normalized)) {
    throw new ConsoleRepositoryError("configuration", `The ${label} is not configured.`);
  }
  return normalized;
}

function safeDevelopmentIdentity(value: string | undefined, fallback: string): string {
  const normalized = value?.trim() || fallback;
  if (!normalized || normalized.length > 512 || !/^[A-Za-z0-9._,@:-]+$/.test(normalized)) {
    throw new ConsoleRepositoryError("configuration", "The local API identity configuration is invalid.");
  }
  return normalized;
}

function requiredBrokerString(record: Record<string, unknown>, key: string, maximum: number): string {
  const value = record[key];
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || /[\r\n\0]/.test(value)) {
    throw new ConsoleRepositoryError("authentication", "The token broker returned an invalid response.");
  }
  return value;
}

function encodeBasicCredentials(clientId: string, clientSecret: string): string {
  return Buffer.from(`${clientId}:${clientSecret}`, "utf8").toString("base64");
}

function pruneTokenCache(nowSeconds: number): void {
  if (brokerTokenCache.size <= 500) return;
  for (const [key, value] of brokerTokenCache) {
    if (value.expiresAt <= nowSeconds || brokerTokenCache.size > 500) brokerTokenCache.delete(key);
  }
}

function isJsonResponse(response: Response): boolean {
  return /^application\/(?:[A-Za-z0-9.-]+\+)?json\b/i.test(response.headers.get("content-type") ?? "");
}

async function responseError(response: Response, requestId: string): Promise<ConsoleRepositoryError> {
  let apiMessage = "";
  let code = "";
  try {
    const text = await readBoundedResponseBody(
      response,
      MAX_ERROR_RESPONSE_BYTES,
      () => invalidResponse(requestId),
    );
    if (isJsonResponse(response) && text) {
      const body = asRecord(JSON.parse(text));
      const detail = body.error ? asRecord(body.error) : body;
      apiMessage = typeof detail.message === "string" ? detail.message : typeof detail.detail === "string" ? detail.detail : "";
      code = typeof detail.code === "string" ? detail.code : "";
    }
  } catch { /* sanitize non-JSON upstream failures */ }
  if (response.status === 401) return new ConsoleRepositoryError("authentication", "The API session could not be authenticated.", false, requestId);
  if (response.status === 403) return new ConsoleRepositoryError("authorization", "Your assigned role does not permit this operation.", false, requestId);
  if (response.status === 409) return new ConsoleRepositoryError("conflict", safeApiMessage(apiMessage, "The operation conflicts with current state."), code === "idempotency_in_progress", requestId);
  if (response.status === 400 || response.status === 422) return new ConsoleRepositoryError("validation", safeApiMessage(apiMessage, "The submitted values were rejected."), false, requestId);
  return new ConsoleRepositoryError("unavailable", "The assurance control plane is temporarily unavailable.", response.status >= 500, requestId);
}

async function readBoundedResponseBody(
  response: Response,
  maximumBytes: number,
  invalid: () => ConsoleRepositoryError,
): Promise<string> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^(?:0|[1-9]\d*)$/.test(declaredLength)) {
      await cancelResponseBody(response);
      throw invalid();
    }
    const parsedLength = Number(declaredLength);
    if (!Number.isSafeInteger(parsedLength) || parsedLength > maximumBytes) {
      await cancelResponseBody(response);
      throw invalid();
    }
  }

  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let receivedBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      receivedBytes += value.byteLength;
      if (receivedBytes > maximumBytes) {
        await reader.cancel();
        throw invalid();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(receivedBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    throw invalid();
  }
}

async function cancelResponseBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // The connection is already closed; there is no response content to retain.
  }
}

function boundedViewError(requestId?: string): ConsoleRepositoryError {
  return new ConsoleRepositoryError(
    "invalid_response",
    "The requested enterprise view exceeds the bounded join window; use a filtered view or a server-side aggregate endpoint.",
    false,
    requestId,
  );
}

function safeApiMessage(message: string, fallback: string): string {
  return message && message.length <= 300 && !/[\r\n]/.test(message) ? message : fallback;
}

function invalidResponse(requestId?: string): ConsoleRepositoryError {
  return new ConsoleRepositoryError("invalid_response", "The assurance control plane returned an invalid response.", true, requestId);
}

function mapPage<T>(
  page: RepositoryValue<{ items: Record<string, unknown>[]; nextCursor: string | null; limit: number }>,
  mapper: (item: Record<string, unknown>) => T,
): RepositoryValue<RepositoryPage<T>> {
  try {
    return { value: { ...page.value, items: page.value.items.map(mapper) }, meta: page.meta };
  } catch (error) {
    if (error instanceof ConsoleRepositoryError) throw error;
    throw invalidResponse(page.meta.requestId);
  }
}

function mapAsset(item: Record<string, unknown>): DatabaseAsset {
  const tags = optionalRecord(item, "tags");
  const platform = platformLabel(requiredString(item, "platform"));
  const status = requiredString(item, "status");
  return {
    id: requiredString(item, "id"),
    name: requiredString(item, "name"),
    platform,
    version: requiredString(item, "version"),
    environment: environmentLabel(requiredString(item, "environment")),
    region: stringValue(tags.region, "Managed estate"),
    owner: requiredString(item, "owner"),
    businessService: stringValue(tags.business_service, "Not assigned"),
    controlCoverage: boundedNumber(tags.control_coverage, 0),
    criticalFindings: boundedNumber(tags.critical_findings, 0),
    lastScan: dateLabel(optionalString(item, "updated_at")),
    health: status === "active" ? "Healthy" : status === "inactive" ? "Offline" : "Attention",
    sensitiveObjects: boundedNumber(tags.sensitive_objects, 0),
  };
}

function mapSensitiveColumn(item: Record<string, unknown>): SensitiveColumn {
  const rawClassification = requiredString(item, "classification");
  const classification =
    rawClassification === "restricted" ? "Restricted" :
    rawClassification === "confidential" ? "Confidential" :
    rawClassification === "internal" ? "Internal" : null;
  if (!classification) throw invalidResponse();
  const rawProtection = requiredString(item, "protection");
  const protection = rawProtection === "unknown" ? "Unknown" : null;
  if (!protection) throw invalidResponse();
  return {
    id: requiredString(item, "id"),
    asset: requiredString(item, "asset_name"),
    platform: platformLabel(requiredString(item, "platform")),
    schema: requiredString(item, "schema"),
    table: requiredString(item, "table"),
    column: requiredString(item, "column"),
    classification,
    dataType: requiredString(item, "data_type"),
    confidence: Math.min(100, Math.max(0, requiredNumber(item, "confidence"))),
    protection,
  };
}

function mapAssessment(item: Record<string, unknown>, assetsById: Map<string, Record<string, unknown>>): Assessment {
  const summary = optionalRecord(item, "summary");
  const rawScore = optionalNumber(item, "score");
  const score = rawScore === null ? null : Math.round(rawScore);
  const status = requiredString(item, "status");
  const collectionStatus = optionalString(summary, "collection_status");
  const asset = assetsById.get(requiredString(item, "asset_id"));
  if (!asset) throw invalidResponse();
  return {
    id: requiredString(item, "id"),
    name: requiredString(item, "control_pack"),
    domain: domainLabel(stringValue(summary.domain, requiredString(item, "control_pack"))),
    platform: platformLabel(requiredString(asset, "platform")),
    status:
      status === "superseded"
        ? "Superseded"
      : status === "queued" || status === "review_required" || (status === "running" && collectionStatus !== "review_required")
        ? "Pending"
        : collectionStatus === "review_required"
          ? "Pending"
        : status === "failed" || (status === "completed" && score !== null && score < 70)
          ? "Failed"
          : status === "completed" && score !== null && score >= 90
            ? "Passed"
            : "Needs attention",
    score,
    passed: boundedNumber(summary.passed, 0),
    warnings: boundedNumber(summary.warnings, 0),
    failed: boundedNumber(summary.failed, status === "failed" ? 1 : 0),
    evidence: boundedNumber(summary.evidence, 0),
    controlCount: boundedNumber(summary.control_count, 0),
    automatedControls: boundedNumber(summary.automated_controls, 0),
    manualControlsPending: boundedNumber(summary.manual_controls_pending, 0),
    collectionCoverage: boundedNumber(summary.collection_coverage, 0),
    collectionErrors: boundedNumber(summary.collection_errors, 0),
    collectionStatus: collectionStatus ?? undefined,
    lastRun: dateLabel(optionalString(item, "updated_at")),
  };
}

function mapAssessmentReview(
  item: Record<string, unknown>,
  assetsById: Map<string, Record<string, unknown>>,
): AssessmentReview {
  const assessmentRecord = asRecord(item.assessment);
  const assetId = requiredString(assessmentRecord, "asset_id");
  const asset = assetsById.get(assetId);
  if (!asset) throw invalidResponse();
  const rawControls = item.controls;
  if (!Array.isArray(rawControls) || rawControls.length > MAX_JOIN_ROWS) {
    throw invalidResponse();
  }
  const controls = rawControls.map((control) => mapAssessmentReviewControl(asRecord(control)));
  const decidedCount = requiredCount(item, "decided_count", MAX_JOIN_ROWS);
  const totalControls = requiredCount(item, "total_controls", MAX_JOIN_ROWS);
  if (
    totalControls !== controls.length ||
    decidedCount > totalControls ||
    controls.filter((control) => control.decision !== null).length !== decidedCount
  ) {
    throw invalidResponse();
  }
  return {
    assessment: mapAssessment(assessmentRecord, assetsById),
    assetName: requiredString(asset, "name"),
    controls,
    decidedCount,
    totalControls,
    readyToFinalize: requiredBoolean(item, "ready_to_finalize"),
    blockingReasons: stringList(item, "blocking_reasons", 100),
  };
}

function mapAssessmentReviewControl(item: Record<string, unknown>): AssessmentReviewControl {
  const definition = mapAssessmentReviewDefinition(asRecord(item.definition));
  const rawCollectionResult = item.collection_result;
  const collectionResult = rawCollectionResult === null || rawCollectionResult === undefined
    ? null
    : mapAssessmentCollectionResult(asRecord(rawCollectionResult));
  const rawDecision = item.decision;
  const decision = rawDecision === null || rawDecision === undefined
    ? null
    : mapAssessmentReviewDecision(asRecord(rawDecision));
  const rawObservations = item.observations;
  if (!Array.isArray(rawObservations) || rawObservations.length > 500) {
    throw invalidResponse();
  }
  const allowedOutcomes = stringList(item, "allowed_outcomes", 3).map(reviewOutcome);
  if (new Set(allowedOutcomes).size !== allowedOutcomes.length) throw invalidResponse();
  return {
    definition,
    collectionResult,
    evidenceIds: stringList(item, "evidence_ids", 1_000),
    observations: rawObservations.map((observation) => mapAssessmentObservation(asRecord(observation))),
    decision,
    allowedOutcomes,
  };
}

function mapAssessmentReviewDefinition(item: Record<string, unknown>): AssessmentReviewDefinition {
  return {
    id: requiredString(item, "id"),
    controlId: requiredString(item, "control_id"),
    domain: domainLabel(requiredString(item, "domain")),
    title: requiredString(item, "title"),
    objective: requiredString(item, "objective"),
    severity: reviewSeverity(requiredString(item, "severity")),
    assessmentMode: requiredString(item, "assessment_mode"),
    manualEvidenceRequirements: stringList(item, "manual_evidence_requirements", 100),
    remediationGuidance: optionalString(item, "remediation_guidance") ?? "No remediation guidance was supplied.",
  };
}

function mapAssessmentCollectionResult(item: Record<string, unknown>): AssessmentCollectionResult {
  return {
    outcome: requiredString(item, "outcome"),
    rationale: optionalString(item, "rationale") ?? "No collection note was supplied.",
    evidenceCount: requiredCount(item, "evidence_count", 1_000),
  };
}

function mapAssessmentReviewDecision(item: Record<string, unknown>): AssessmentReviewDecision {
  return {
    outcome: reviewOutcome(requiredString(item, "outcome")),
    rationale: requiredString(item, "rationale"),
  };
}

function mapAssessmentObservation(item: Record<string, unknown>): AssessmentObservation {
  const entries = Object.entries(item);
  if (!entries.length || entries.length > 100) throw invalidResponse();
  const observation: Record<string, string | number | boolean | null> = {};
  for (const [key, value] of entries) {
    if (!key || key.length > 160) throw invalidResponse();
    observation[key] = observationValue(value);
  }
  return observation;
}

function observationValue(value: unknown): string | number | boolean | null {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.length <= 8_000) return value;
  if (Array.isArray(value) && value.length <= 100) {
    return value.map(observationScalar).join(", ").slice(0, 8_000);
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > 100) throw invalidResponse();
    return entries
      .map(([key, nested]) => `${key}: ${observationScalar(nested)}`)
      .join("; ")
      .slice(0, 8_000);
  }
  throw invalidResponse();
}

function observationScalar(value: unknown): string {
  if (value === null) return "Not reported";
  if (typeof value === "string" && value.length <= 2_000) return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (typeof value === "boolean") return value ? "Yes" : "No";
  throw invalidResponse();
}

function mapFinding(item: Record<string, unknown>, assetsById: Map<string, Record<string, unknown>>): Finding {
  const assetId = requiredString(item, "asset_id");
  const asset = assetsById.get(assetId);
  if (!asset) throw invalidResponse();
  const riskContext = optionalRecord(item, "risk_context");
  return {
    id: requiredString(item, "id"),
    assessmentId: requiredString(item, "assessment_id"),
    title: requiredString(item, "title"),
    severity: severityLabel(requiredString(item, "severity")),
    status: findingStatusLabel(requiredString(item, "status")),
    platform: platformLabel(requiredString(asset, "platform")),
    asset: requiredString(asset, "name"),
    control: requiredString(item, "control_id"),
    owner: optionalString(item, "owner") ?? "Unassigned",
    dueDate: dateLabel(optionalString(item, "due_at")),
    dueAt: optionalString(item, "due_at") ?? undefined,
    evidence: stringValue(riskContext.evidence, requiredString(item, "description")),
    remediation: requiredString(item, "remediation"),
  };
}

function mapConnector(item: Record<string, unknown>, assetsById: Map<string, Record<string, unknown>>): Connector {
  const config = optionalRecord(item, "config");
  const asset = assetsById.get(requiredString(item, "asset_id"));
  const status = requiredString(item, "status");
  const name = requiredString(item, "name");
  const localMySql = name.startsWith("local-mysql-");
  return {
    id: requiredString(item, "id"),
    assetId: requiredString(item, "asset_id"),
    name,
    platform: platformLabel(requiredString(item, "platform")),
    version: stringValue(config.version, "managed"),
    region: stringValue(config.region, asset ? stringValue(optionalRecord(asset, "tags").region, "Managed estate") : "Managed estate"),
    assets: 1,
    status: status === "online" ? "Online" : status === "offline" ? "Offline" : "Degraded",
    lastHeartbeat: dateLabel(optionalString(item, "last_heartbeat_at")),
    nextScan: stringValue(config.next_scan, localMySql ? "Daily on local stack start" : "Run on demand"),
    serviceAccount: stringValue(config.service_account, localMySql ? "assurance_hub_ro" : "Managed collector identity"),
    releaseChannel: config.release_channel === "controlled" ? "Controlled" : "Stable",
    capabilities: stringList(item, "capabilities", 100),
  };
}

function mapMaskingPolicy(item: Record<string, unknown>): MaskingPolicy {
  const parameters = optionalRecord(item, "parameters");
  const rawWorkflowStatus = stringValue(parameters.workflow_status, item.enabled === false ? "draft" : optionalString(item, "approved_by") ? "approved" : "draft");
  const workflowStatus = ["draft", "approved", "execution_recorded", "validated"].includes(rawWorkflowStatus)
    ? rawWorkflowStatus as NonNullable<MaskingPolicy["workflowStatus"]>
    : "draft";
  const archivedAt = optionalString(parameters, "archived_at") ?? undefined;
  const status: MaskingPolicy["status"] = archivedAt
    ? "Archived"
    : workflowStatus === "validated"
      ? "Validated"
    : workflowStatus === "execution_recorded"
      ? "Execution recorded"
      : workflowStatus === "approved"
        ? "Approved"
        : "Draft";
  const rawCopyStatus = optionalString(parameters, "copy_status");
  const copyStatus = rawCopyStatus && ["queued", "running", "retry_pending", "failed", "automated_checks_passed"].includes(rawCopyStatus)
    ? rawCopyStatus as NonNullable<MaskingPolicy["copyStatus"]>
    : undefined;
  const sourceDatabase = optionalString(parameters, "source_database") ?? optionalString(parameters, "source_asset") ?? undefined;
  const targetDatabase = optionalString(parameters, "target_database") ?? undefined;
  const isBuiltinLocalCopy = (
    parameters.local_copy_plan === true
    || requiredString(item, "name") === "insurance_sample local masking plan"
  ) && sourceDatabase === "insurance_sample";
  return {
    id: requiredString(item, "id"),
    name: requiredString(item, "name"),
    classification: requiredString(item, "classification"),
    technique: requiredString(item, "strategy").replaceAll("_", " "),
    coverage: boundedNumber(parameters.coverage, 0),
    datasets: boundedNumber(parameters.datasets, 0),
    environment: requiredString(item, "target_environment").replaceAll("_", " "),
    status,
    lastValidated: workflowStatus === "validated" ? dateLabel(optionalString(parameters, "validated_at")) : "Not validated",
    workflowStatus,
    lastNote: optionalString(parameters, "last_note") ?? undefined,
    executionReference: optionalString(parameters, "execution_reference") ?? undefined,
    isBuiltinLocalCopy,
    copyStatus,
    sourceDatabase,
    targetDatabase: targetDatabase ?? (isBuiltinLocalCopy ? "insurance_sample_masked" : undefined),
    rowCap: isBuiltinLocalCopy ? boundedNumber(parameters.row_cap, 500) : undefined,
    tablesCopied: copyStatus === "automated_checks_passed" ? boundedNumber(parameters.tables_copied, 0) : undefined,
    rowsCopied: copyStatus === "automated_checks_passed" ? boundedNumber(parameters.rows_copied, 0) : undefined,
    columnsMasked: copyStatus === "automated_checks_passed" ? boundedNumber(parameters.columns_masked, 0) : undefined,
    valuesMasked: copyStatus === "automated_checks_passed" ? boundedNumber(parameters.values_masked, 0) : undefined,
    automatedChecksPassed: parameters.automated_checks_passed === true,
    archived: Boolean(archivedAt),
    archivedAt,
  };
}

function mapControlPack(item: Record<string, unknown>): ControlPackOption {
  const status = requiredString(item, "status");
  if (!["active", "draft", "retired"].includes(status)) throw invalidResponse();
  return {
    id: requiredString(item, "id"),
    title: requiredString(item, "title"),
    version: requiredString(item, "version"),
    platform: platformLabel(requiredString(item, "platform")),
    status: status as ControlPackOption["status"],
  };
}

function buildAssessmentTargets(
  options: Omit<AssessmentActionOptions, "targets">,
  requestId?: string,
): AssessmentTargetOption[] {
  const assetsById = new Map(options.assets.map((asset) => [asset.id, asset]));
  const activePacksByPlatform = new Map<Platform, ControlPackOption[]>();
  for (const pack of options.controlPacks) {
    if (pack.status !== "active") continue;
    const platformPacks = activePacksByPlatform.get(pack.platform) ?? [];
    platformPacks.push(pack);
    activePacksByPlatform.set(pack.platform, platformPacks);
  }

  const targets: AssessmentTargetOption[] = [];
  const seenTargets = new Set<string>();
  for (const connector of options.connectors) {
    if (!connector.assetId || connector.status !== "Online") continue;
    // Internal workers such as the masking-copy connector are never assessment targets.
    // Only a connector that advertises the read-only metadata capability can run a pack.
    if (!connector.capabilities?.includes("read_only_metadata")) continue;
    const asset = assetsById.get(connector.assetId);
    if (!asset || connector.platform !== asset.platform) continue;
    for (const pack of activePacksByPlatform.get(asset.platform) ?? []) {
      const id = `${asset.id}:${connector.id}:${pack.id}`;
      if (seenTargets.has(id)) throw invalidResponse(requestId);
      if (targets.length >= MAX_JOIN_ROWS) throw boundedViewError(requestId);
      seenTargets.add(id);
      targets.push({
        id,
        assetName: asset.name,
        connectorName: connector.name,
        controlPackTitle: pack.title,
        controlPackVersion: pack.version,
        platform: asset.platform,
      });
    }
  }
  return targets.sort((left, right) =>
    left.assetName.localeCompare(right.assetName)
    || left.connectorName.localeCompare(right.connectorName)
    || left.controlPackTitle.localeCompare(right.controlPackTitle)
    || left.controlPackVersion.localeCompare(right.controlPackVersion),
  );
}

function mapAccessReview(item: Record<string, unknown>, assetsById: Map<string, Record<string, unknown>>): AccessReview {
  const scope = optionalRecord(item, "scope");
  const assetId = requiredString(item, "asset_id");
  const asset = assetsById.get(assetId);
  if (!asset) throw invalidResponse();
  return {
    id: requiredString(item, "id"),
    principal: stringValue(scope.principal, requiredString(item, "name")),
    principalType: scope.principal_type === "human" ? "Human" : scope.principal_type === "role" ? "Database role" : "Service account",
    platform: platformLabel(requiredString(asset, "platform")),
    asset: requiredString(asset, "name"),
    access: stringValue(scope.access, "Review scope defined by policy"),
    risk: severityLabel(stringValue(scope.risk, "medium")),
    lastUsed: stringValue(scope.last_used, "Not reported"),
    recommendation: stringValue(scope.recommendation, `Complete by ${dateLabel(optionalString(item, "due_at"))}`),
    checkedAt: scope.checked_at ? dateLabel(stringValue(scope.checked_at, "")) : "Not checked",
    reviewer: optionalString(item, "reviewer") ?? undefined,
    reviewStatus: accessReviewStatus(requiredString(item, "status")),
    scanScope: optionalString(scope, "scan_scope") ?? undefined,
  };
}

function accessReviewStatus(status: string): NonNullable<AccessReview["reviewStatus"]> {
  if (status === "draft") return "Draft";
  if (status === "in_review") return "In review";
  if (status === "approved") return "Approved";
  if (status === "remediation_required") return "Remediation required";
  if (status === "closed") return "Closed";
  throw invalidResponse();
}

function mapEvidence(
  item: Record<string, unknown>,
  assessmentsById: Map<string, Record<string, unknown>>,
  assetsById: Map<string, Record<string, unknown>>,
): EvidenceRecord {
  const assessment = assessmentsById.get(requiredString(item, "assessment_id"));
  const asset = assessment ? assetsById.get(requiredString(assessment, "asset_id")) : undefined;
  if (!assessment || !asset) throw invalidResponse();
  return {
    id: requiredString(item, "id"),
    assessmentId: requiredString(item, "assessment_id"),
    control: requiredString(item, "control_id"),
    asset: requiredString(asset, "name"),
    platform: platformLabel(requiredString(asset, "platform")),
    source: requiredString(item, "evidence_type").replaceAll("_", " "),
    collectedAt: dateLabel(optionalString(item, "collected_at")),
    integrity: /^[a-f0-9]{64}$/i.test(requiredString(item, "sha256")) ? "Digest recorded" : "Missing digest",
    retention: stringValue(optionalRecord(item, "attributes").retention, "Policy managed"),
  };
}

function deriveControlDomains(assessmentRows: Record<string, unknown>[], findingRows: Record<string, unknown>[]): ControlDomain[] {
  const domains = [
    { name: "Database encryption", key: "encryption" },
    { name: "Data protection", key: "data_protection" },
    { name: "Access security", key: "access_security" },
    { name: "Data masking", key: "data_masking" },
  ] as const;
  return domains.map(({ name, key }) => {
    const scored = assessmentRows
      .map((item) => ({ item, summary: optionalRecord(item, "summary") }))
      .filter(({ summary }) => optionalNumber(summary, `domain_${key}_score`) !== null);
    const scores = scored
      .map(({ summary }) => optionalNumber(summary, `domain_${key}_score`))
      .filter((score): score is number => score !== null);
    return {
      name,
      score: scores.length ? Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length) : 0,
      scoreAvailable: scores.length > 0,
      change: 0,
      controls: scored.length,
      findings: findingRows.filter((item) =>
        requiredString(item, "domain") === key &&
        !["resolved", "false_positive"].includes(requiredString(item, "status"))
      ).length,
    };
  });
}

function latestCompletedAssessments(rows: Record<string, unknown>[]): Record<string, unknown>[] {
  const latest = new Map<string, Record<string, unknown>>();
  for (const item of rows.filter((row) =>
    requiredString(row, "status") === "completed" && optionalNumber(row, "score") !== null
  ).sort(compareAssessmentTime)) {
    latest.set(requiredString(item, "asset_id"), item);
  }
  return [...latest.values()];
}

function compareAssessmentTime(left: Record<string, unknown>, right: Record<string, unknown>): number {
  return assessmentTimestamp(left) - assessmentTimestamp(right);
}

function assessmentTimestamp(item: Record<string, unknown>): number {
  const value = optionalString(item, "completed_at") ?? optionalString(item, "updated_at");
  const parsed = value ? Date.parse(value) : Number.NaN;
  return Number.isFinite(parsed) ? parsed : 0;
}

function deriveActivity(assessmentRows: Record<string, unknown>[], findingRows: Record<string, unknown>[]): ActivityRow[] {
  const assessmentActivity = assessmentRows.slice(-3).reverse().map((item) => ({
    time: timeLabel(optionalString(item, "updated_at")),
    title: `${requiredString(item, "control_pack")} assessment ${requiredString(item, "status")}`,
    detail: `Assessment ${requiredString(item, "id").slice(0, 8)}`,
    tone: requiredString(item, "status") === "failed" ? "critical" as const : "info" as const,
  }));
  const findingActivity = findingRows.slice(-2).reverse().map((item) => ({
    time: timeLabel(optionalString(item, "updated_at")),
    title: requiredString(item, "title"),
    detail: `${requiredString(item, "severity")} finding`,
    tone: requiredString(item, "severity") === "critical" ? "critical" as const : "warning" as const,
  }));
  return [...assessmentActivity, ...findingActivity].slice(0, 5);
}

function mergeMeta(...metas: RepositoryMeta[]): RepositoryMeta {
  return {
    source: metas.some((meta) => meta.source === "live-api") ? "live-api" : "development-fixture",
    fetchedAt: metas.map((meta) => meta.fetchedAt).sort().at(-1) ?? new Date().toISOString(),
    stale: metas.some((meta) => meta.stale),
    requestId: metas.find((meta) => meta.requestId)?.requestId,
  };
}

function liveMeta(): RepositoryMeta {
  return { source: "live-api", fetchedAt: new Date().toISOString(), stale: false };
}

function normalizeLimit(value?: number): number {
  if (!Number.isInteger(value) || !value) return DEFAULT_PAGE_SIZE;
  return Math.max(1, Math.min(value, MAX_PAGE_SIZE));
}

function normalizeCursor(value?: string): string | undefined {
  if (!value) return undefined;
  if (value.length > 512 || [...value].some((character) => character.charCodeAt(0) <= 31 || character.charCodeAt(0) === 127)) {
    throw new ConsoleRepositoryError("validation", "The pagination cursor is invalid.");
  }
  return value;
}

function resourceId(value: string): string {
  if (!/^[a-f0-9-]{36}$/i.test(value)) {
    throw new ConsoleRepositoryError("validation", "The assessment identifier is invalid.");
  }
  return value;
}

function apiFindingStatus(value: string): string | undefined {
  return ({
    Open: "open",
    "In remediation": "in_progress",
    "Risk accepted": "risk_accepted",
    Resolved: "resolved",
    "False positive": "false_positive",
  } as Record<string, string>)[value];
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw invalidResponse();
  return value as Record<string, unknown>;
}

function optionalRecord(record: Record<string, unknown>, key: string): Record<string, unknown> {
  const value = record[key];
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function requiredString(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string" || !value || value.length > 8_000) throw invalidResponse();
  return value;
}

function optionalString(record: Record<string, unknown>, key: string): string | null {
  const value = record[key];
  if (value === null || value === undefined) return null;
  if (typeof value !== "string" || value.length > 8_000) throw invalidResponse();
  return value;
}

function requiredNumber(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  if (typeof value !== "number" || !Number.isFinite(value)) throw invalidResponse();
  return value;
}

function optionalNumber(record: Record<string, unknown>, key: string): number | null {
  const value = record[key];
  if (value === null || value === undefined) return null;
  if (typeof value !== "number" || !Number.isFinite(value)) throw invalidResponse();
  return value;
}

function requiredCount(record: Record<string, unknown>, key: string, maximum: number): number {
  const value = requiredNumber(record, key);
  if (!Number.isInteger(value) || value < 0 || value > maximum) throw invalidResponse();
  return value;
}

function requiredBoolean(record: Record<string, unknown>, key: string): boolean {
  const value = record[key];
  if (typeof value !== "boolean") throw invalidResponse();
  return value;
}

function stringList(record: Record<string, unknown>, key: string, maximum: number): string[] {
  const value = record[key];
  if (!Array.isArray(value) || value.length > maximum) throw invalidResponse();
  return value.map((entry) => {
    if (typeof entry !== "string" || !entry || entry.length > 8_000) throw invalidResponse();
    return entry;
  });
}

function boundedNumber(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.max(0, Math.round(value)) : fallback;
}

function stringValue(value: unknown, fallback: string): string {
  return typeof value === "string" && value.length > 0 && value.length <= 8_000 ? value : fallback;
}

function platformLabel(value: string): Platform {
  if (value === "oracle") return "Oracle";
  if (value === "postgresql") return "PostgreSQL";
  if (value === "sybase") return "Sybase ASE";
  if (value === "mysql") return "MySQL";
  throw invalidResponse();
}

function environmentLabel(value: string): DatabaseAsset["environment"] {
  if (value === "production") return "Production";
  if (value === "development") return "Development";
  if (["staging", "test", "disaster_recovery"].includes(value)) return "Pre-production";
  throw invalidResponse();
}

function severityLabel(value: string): Finding["severity"] {
  if (value === "critical") return "Critical";
  if (value === "high") return "High";
  if (value === "medium") return "Medium";
  return "Low";
}

function reviewSeverity(value: string): AssessmentReviewDefinition["severity"] {
  if (!["critical", "high", "medium", "low"].includes(value)) throw invalidResponse();
  return severityLabel(value);
}

function reviewOutcome(value: string): ReviewOutcome {
  if (value === "passed" || value === "failed" || value === "not_applicable") return value;
  throw invalidResponse();
}

function findingStatusLabel(value: string): Finding["status"] {
  if (value === "open") return "Open";
  if (value === "in_progress") return "In remediation";
  if (value === "risk_accepted") return "Risk accepted";
  if (value === "false_positive") return "False positive";
  if (value === "resolved") return "Resolved";
  throw invalidResponse();
}

function domainLabel(value: string): Assessment["domain"] {
  const normalized = value.toLowerCase().replaceAll("_", " ");
  if (normalized.includes("mask")) return "Data masking";
  if (normalized.includes("access") || normalized.includes("identity") || normalized.includes("privilege")) return "Access security";
  if (normalized.includes("encrypt") || normalized.includes("tls")) return "Encryption";
  return "Data protection";
}

function dateLabel(value: string | null): string {
  if (!value) return "Not reported";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "Not reported" : new Intl.DateTimeFormat("en-IN", { dateStyle: "medium", timeStyle: "short", timeZone: "Asia/Kolkata" }).format(date);
}

function timeLabel(value: string | null): string {
  if (!value) return "--:--";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "--:--" : new Intl.DateTimeFormat("en-IN", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone: "Asia/Kolkata",
  }).format(date);
}

function newestTimestamp(rows: Record<string, unknown>[]): string {
  const newest = rows.map((item) => optionalString(item, "updated_at")).filter((value): value is string => Boolean(value)).sort().at(-1) ?? null;
  return dateLabel(newest);
}

async function boundedBackoff(attempt: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 75 * 2 ** (attempt - 1) + Math.floor(Math.random() * 50)));
}
