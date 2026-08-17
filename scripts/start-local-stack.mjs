import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import {
  assertLocalSyntheticCollectionBoundary,
  LOCAL_SYNTHETIC_COLLECTOR_ID,
  LOCAL_SYNTHETIC_LAUNCH_SOURCE,
  LOCAL_SYNTHETIC_TENANT_ID,
} from "./local-synthetic-collection.mjs";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const apiDirectory = join(repositoryRoot, "services", "api");
const apiPort = boundedPort(process.env.ASSURANCE_LOCAL_API_PORT ?? "8000");
const apiBaseUrl = `http://127.0.0.1:${apiPort}`;
const python = resolvePython();
const children = new Set();
let stopping = false;
const localMySqlMode = Boolean(process.env.ASSURANCE_LOCAL_MYSQL_ENV_FILE?.trim());
const inheritedEnvironment = environmentWithoutAzureSql(process.env);

const apiEnvironment = {
  ...inheritedEnvironment,
  ENVIRONMENT: "development",
  AUTH_MODE: "development",
  ALLOW_INSECURE_DEV_AUTH: "true",
  DATABASE_URL:
    process.env.ASSURANCE_LOCAL_DATABASE_URL ??
    "sqlite+aiosqlite:///./assurance-local.db",
  DATABASE_MAINTENANCE_URL: "",
  OTEL_EXPORTER_OTLP_ENDPOINT: "",
  SEED_DEMO_DATA: process.env.ASSURANCE_SEED_DEMO_DATA ?? "true",
};

assertLocalSyntheticCollectionBoundary({
  launchSource: LOCAL_SYNTHETIC_LAUNCH_SOURCE,
  apiBaseUrl,
  apiDirectory,
  databaseUrl: apiEnvironment.DATABASE_URL,
  environment: apiEnvironment.ENVIRONMENT,
  authMode: apiEnvironment.AUTH_MODE,
  allowInsecureDevAuth: apiEnvironment.ALLOW_INSECURE_DEV_AUTH,
  tenantId: LOCAL_SYNTHETIC_TENANT_ID,
  collectorId: LOCAL_SYNTHETIC_COLLECTOR_ID,
});

await runChecked(
  python,
  ["-m", "alembic", "upgrade", "head"],
  apiDirectory,
  apiEnvironment,
  "Local API migration failed",
);

const api = spawn(
  python,
  [
    "-m",
    "uvicorn",
    "assurance_hub.main:app",
    "--host",
    "127.0.0.1",
    "--port",
    String(apiPort),
    "--no-access-log",
  ],
  { cwd: apiDirectory, env: apiEnvironment, stdio: "inherit" },
);
children.add(api);
api.on("error", (error) => stopWithError(`Unable to start the local API: ${error.message}`));
api.on("exit", (code, signal) => {
  children.delete(api);
  if (!stopping) stopWithError(`Local API exited (${signal ?? code ?? "unknown"}).`);
});

await waitForApi(apiBaseUrl, api);
await seedControlPacks(apiBaseUrl);

let mysqlCollector;
let mysqlMasker;
if (localMySqlMode) {
  const source = await bootstrapLocalMySql(process.env.ASSURANCE_LOCAL_MYSQL_ENV_FILE);
  await registerLocalMySql(apiBaseUrl, source);
  mysqlCollector = startLocalMySqlCollector(source);
  mysqlMasker = startLocalMySqlMasker(source);
}

if (!localMySqlMode) {
  const syntheticCollector = spawn(
    python,
    [join(repositoryRoot, "tools", "local_synthetic_collector.py")],
    {
      cwd: repositoryRoot,
      stdio: "inherit",
      env: {
        ...apiEnvironment,
        PYTHONUNBUFFERED: "1",
        LOCAL_SYNTHETIC_LAUNCH_SOURCE,
        LOCAL_SYNTHETIC_API_BASE_URL: apiBaseUrl,
        LOCAL_SYNTHETIC_API_DIRECTORY: apiDirectory,
        LOCAL_SYNTHETIC_DATABASE_URL: apiEnvironment.DATABASE_URL,
        LOCAL_SYNTHETIC_TENANT_ID,
        LOCAL_SYNTHETIC_COLLECTOR_ID,
      },
    },
  );
  children.add(syntheticCollector);
  syntheticCollector.on("error", (error) =>
    stopWithError(`Unable to start local synthetic collection: ${error.message}`),
  );
  syntheticCollector.on("exit", (code, signal) => {
    children.delete(syntheticCollector);
    if (!stopping) {
      stopWithError(`Local synthetic collection exited (${signal ?? code ?? "unknown"}).`);
    }
  });
}

if (mysqlCollector) {
  children.add(mysqlCollector);
  mysqlCollector.on("error", (error) =>
    stopWithError(`Unable to start the local MySQL collector: ${error.message}`),
  );
  mysqlCollector.on("exit", (code, signal) => {
    children.delete(mysqlCollector);
    if (!stopping) stopWithError(`Local MySQL collector exited (${signal ?? code ?? "unknown"}).`);
  });
}

if (mysqlMasker) {
  children.add(mysqlMasker);
  mysqlMasker.on("error", (error) =>
    stopWithError(`Unable to start the dedicated local MySQL masker: ${error.message}`),
  );
  mysqlMasker.on("exit", (code, signal) => {
    children.delete(mysqlMasker);
    if (!stopping) {
      stopWithError(`Dedicated local MySQL masker exited (${signal ?? code ?? "unknown"}).`);
    }
  });
}

const web = spawn(
  process.execPath,
  [join(repositoryRoot, "scripts", "start-local-dev.mjs"), ...process.argv.slice(2)],
  {
    cwd: repositoryRoot,
    stdio: "inherit",
    env: {
      ...inheritedEnvironment,
      CONSOLE_DATA_MODE: "api",
      ASSURANCE_API_BASE_URL: apiBaseUrl,
      AEGISDB_DEVELOPMENT_TENANT_ID: LOCAL_SYNTHETIC_TENANT_ID,
      AEGISDB_DEVELOPMENT_ROLES: "admin,security_analyst,database_owner",
      AEGISDB_LOCAL_SYNTHETIC_COLLECTION: localMySqlMode ? "false" : "true",
      AEGISDB_LOCAL_MYSQL_MODE: localMySqlMode ? "true" : "false",
    },
  },
);
children.add(web);
web.on("error", (error) => stopWithError(`Unable to start the local console: ${error.message}`));
web.on("exit", (code, signal) => {
  children.delete(web);
  if (!stopping) stop(code ?? (signal ? 1 : 0));
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => stop(0));
}

function boundedPort(raw) {
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error("ASSURANCE_LOCAL_API_PORT must be an integer from 1024 to 65535");
  }
  return port;
}

function scalarMapsEqual(left, right) {
  if (!left || typeof left !== "object" || Array.isArray(left)) return false;
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return (
    JSON.stringify(leftKeys) === JSON.stringify(rightKeys) &&
    leftKeys.every((key) => left[key] === right[key])
  );
}

function resolvePython() {
  const configured = process.env.ASSURANCE_API_PYTHON?.trim();
  const candidates = [
    configured,
    join(apiDirectory, ".venv", "Scripts", "python.exe"),
    join(apiDirectory, ".venv", "bin", "python"),
  ].filter(Boolean);
  const selected = candidates.find((candidate) => existsSync(candidate));
  if (!selected) {
    throw new Error(
      "The API virtual environment is missing. Create services/api/.venv and install services/api[dev,sqlite,observability].",
    );
  }
  return selected;
}

function runChecked(command, args, cwd, env, failureMessage) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { cwd, env, stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`${failureMessage} (exit ${code ?? "unknown"})`));
    });
  });
}

function runCaptured(command, args, cwd, env, failureMessage) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { cwd, env, stdio: ["ignore", "pipe", "inherit"] });
    const chunks = [];
    child.stdout.on("data", (chunk) => chunks.push(chunk));
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) resolvePromise(Buffer.concat(chunks).toString("utf8"));
      else reject(new Error(`${failureMessage} (exit ${code ?? "unknown"})`));
    });
  });
}

async function bootstrapLocalMySql(envFile) {
  const credentialRoot = join(repositoryRoot, ".local-secrets", "mysql");
  const raw = await runCaptured(
    python,
    [
      join(repositoryRoot, "tools", "bootstrap_local_mysql.py"),
      "--env-file",
      resolve(envFile),
      "--credential-root",
      credentialRoot,
    ],
    repositoryRoot,
    apiEnvironment,
    "Local MySQL read-only account bootstrap failed",
  );
  const source = assertSanitizedLocalMySqlBootstrap(JSON.parse(raw), credentialRoot);
  console.log(
    `Verified read-only local MySQL source ${source.database} (${source.table_count} tables, ${source.version}).`,
  );
  return source;
}

function assertSanitizedLocalMySqlBootstrap(source, credentialRoot) {
  if (!source || typeof source !== "object" || Array.isArray(source)) {
    throw new Error("Local MySQL bootstrap returned an invalid result");
  }
  if (
    !["localhost", "127.0.0.1"].includes(source.host) ||
    !Number.isInteger(source.port) ||
    source.port < 1 ||
    source.port > 65_535 ||
    source.database !== "insurance_sample" ||
    source.target_database !== "insurance_sample_masked" ||
    source.staging_database !== "insurance_sample_masked_staging" ||
    source.target_database_prefix !== "insurance_sample_masked_" ||
    source.staging_database_prefix !== "aegisdb_mask_stage_" ||
    source.reader_account !== "assurance_hub_ro" ||
    source.target_writer_account !== "assurance_hub_mask_writer" ||
    source.target_reader_account !== "insurance_masked_test_ro" ||
    JSON.stringify(source.privileges) !== JSON.stringify(["SELECT", "SHOW VIEW"]) ||
    JSON.stringify(source.target_reader_privileges) !==
      JSON.stringify(["SELECT", "SHOW VIEW"])
  ) {
    throw new Error("Local MySQL bootstrap crossed the fixed masking boundary");
  }
  const approvedRoot = resolve(credentialRoot);
  if (resolve(String(source.credential_root)) !== approvedRoot) {
    throw new Error("Local MySQL bootstrap returned an unexpected credential root");
  }
  const projectedFiles = [
    source.secret_file,
    source.target_secret_file,
    source.target_reader_secret_file,
    source.masking_key_file,
  ].map((value) => resolve(String(value)));
  if (
    new Set(projectedFiles).size !== projectedFiles.length ||
    projectedFiles.some((value) => dirname(value) !== approvedRoot)
  ) {
    throw new Error("Local MySQL bootstrap returned an unsafe projection path");
  }
  if (Object.hasOwn(source, "password")) {
    throw new Error("Local MySQL bootstrap must never return credentials inline");
  }
  return source;
}

async function registerLocalMySql(baseUrl, source) {
  const assetsResponse = await fetch(`${baseUrl}/api/v1/assets?limit=100`, {
    headers: developmentHeaders(),
    signal: AbortSignal.timeout(5_000),
  });
  if (!assetsResponse.ok) throw new Error("Unable to inspect local MySQL assets");
  const assetsBody = await assetsResponse.json();
  let asset = assetsBody.items.find(
    (item) => item.external_id === "local-mysql-insurance-sample",
  );
  if (!asset) {
    const response = await fetch(`${baseUrl}/api/v1/assets`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "idempotency-key": "local-mysql-insurance-sample-asset-v1",
        ...developmentHeaders(),
      },
      body: JSON.stringify({
        external_id: "local-mysql-insurance-sample",
        name: source.database,
        platform: "mysql",
        version: source.version,
        edition: "Local MySQL",
        environment: "development",
        owner: "Local Database Owner",
        criticality: "medium",
        tags: { source: "local", data_profile: "500-row-table-sample" },
      }),
    });
    if (!response.ok) throw new Error(`Unable to register local MySQL asset: ${response.status}`);
    asset = await response.json();
  }

  const connectorsResponse = await fetch(`${baseUrl}/api/v1/connectors?limit=100`, {
    headers: developmentHeaders(),
    signal: AbortSignal.timeout(5_000),
  });
  if (!connectorsResponse.ok) throw new Error("Unable to inspect local MySQL connectors");
  const connectorsBody = await connectorsResponse.json();
  const connectorName = "local-mysql-insurance-sample";
  let connector = connectorsBody.items.find((item) => item.name === connectorName);
  if (!connector) {
    const response = await fetch(`${baseUrl}/api/v1/connectors`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "idempotency-key": "local-mysql-insurance-sample-connector-v1",
        ...developmentHeaders(),
      },
      body: JSON.stringify({
        asset_id: asset.id,
        name: connectorName,
        platform: "mysql",
        endpoint_ref: `dns://${source.host}:${source.port}/${source.database}`,
        secret_ref: source.secret_ref,
        collector_id: "local-mysql-collector",
        capabilities: ["read_only_metadata", "mysql"],
        config: {
          enabled: true,
          region: "Local workstation",
          version: "local",
          release_channel: "controlled",
          next_scan: "Daily on local stack start",
          service_account: source.reader_account,
        },
      }),
    });
    if (!response.ok) throw new Error(`Unable to register local MySQL connector: ${response.status}`);
    connector = await response.json();
  }

  const maskingConnectorName = "local-mysql-insurance-sample-masking-copy";
  const maskingEndpoint = `dns://${source.host}:${source.port}/${source.database}`;
  const expectedMaskingConfig = {
    enabled: true,
    region: "Local workstation",
    version: "local",
    source_database: source.database,
    target_database_prefix: source.target_database_prefix,
    staging_database_prefix: source.staging_database_prefix,
    row_cap: 500,
    service_account: source.target_writer_account,
  };
  let maskingConnector = connectorsBody.items.find(
    (item) => item.name === maskingConnectorName,
  );
  if (!maskingConnector) {
    const response = await fetch(`${baseUrl}/api/v1/connectors`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "idempotency-key": "local-mysql-insurance-sample-masking-copy-connector-v1",
        ...developmentHeaders(),
      },
      body: JSON.stringify({
        asset_id: asset.id,
        name: maskingConnectorName,
        platform: "mysql",
        endpoint_ref: maskingEndpoint,
        secret_ref: source.target_writer_secret_ref,
        collector_id: "local-mysql-masker",
        capabilities: ["masking_copy"],
        config: expectedMaskingConfig,
      }),
    });
    if (!response.ok) {
      throw new Error(`Unable to register local MySQL masking connector: ${response.status}`);
    }
    maskingConnector = await response.json();
  } else {
    const immutableBoundaryIsSafe =
      maskingConnector.asset_id === asset.id &&
      maskingConnector.name === maskingConnectorName &&
      maskingConnector.platform === "mysql" &&
      maskingConnector.collector_id === "local-mysql-masker" &&
      maskingConnector.endpoint_ref === maskingEndpoint &&
      maskingConnector.capabilities.length === 1 &&
      maskingConnector.capabilities[0] === "masking_copy";
    if (!immutableBoundaryIsSafe) {
      throw new Error("The dedicated local MySQL masking connector has an unsafe identity");
    }
    if (!scalarMapsEqual(maskingConnector.config, expectedMaskingConfig)) {
      const response = await fetch(
        `${baseUrl}/api/v1/connectors/${maskingConnector.id}/config`,
        {
          method: "PATCH",
          headers: {
            "content-type": "application/json",
            "idempotency-key":
              "local-mysql-insurance-sample-masking-copy-prefix-config-v1",
            ...developmentHeaders(),
          },
          body: JSON.stringify({ config: expectedMaskingConfig }),
        },
      );
      if (!response.ok) {
        throw new Error(
          `Unable to upgrade local MySQL masking connector config: ${response.status}`,
        );
      }
      maskingConnector = await response.json();
    }
  }
  const maskingRuntimeResponse = await fetch(
    `${baseUrl}/api/v1/collectors/connectors/${maskingConnector.id}/runtime-config`,
    {
      headers: collectorHeaders("local-mysql-masker"),
      signal: AbortSignal.timeout(5_000),
    },
  );
  if (!maskingRuntimeResponse.ok) {
    throw new Error(
      `Unable to verify local MySQL masking runtime config: ${maskingRuntimeResponse.status}`,
    );
  }
  const maskingRuntime = await maskingRuntimeResponse.json();
  if (
    maskingConnector.asset_id !== asset.id ||
    maskingConnector.name !== maskingConnectorName ||
    maskingConnector.platform !== "mysql" ||
    maskingConnector.collector_id !== "local-mysql-masker" ||
    maskingConnector.endpoint_ref !== maskingEndpoint ||
    maskingConnector.capabilities.length !== 1 ||
    maskingConnector.capabilities[0] !== "masking_copy" ||
    maskingConnector.config?.enabled === false ||
    maskingRuntime.connector_id !== maskingConnector.id ||
    maskingRuntime.platform !== "mysql" ||
    maskingRuntime.endpoint_ref !== maskingConnector.endpoint_ref ||
    maskingRuntime.secret_ref !== source.target_writer_secret_ref ||
    maskingRuntime.config?.source_database !== source.database ||
    maskingRuntime.config?.target_database_prefix !== source.target_database_prefix ||
    maskingRuntime.config?.staging_database_prefix !== source.staging_database_prefix ||
    maskingRuntime.config?.row_cap !== 500
  ) {
    throw new Error("The dedicated local MySQL masking connector has an unsafe configuration");
  }
  await scheduleLocalMySqlDiscovery(baseUrl, connector.id);
  await scheduleLocalMySqlBaseline(baseUrl, asset.id, connector.id);
  await scheduleLocalMySqlAccessReview(baseUrl, connector.id);
  await ensureLocalMySqlMaskingPolicy(baseUrl, source);
  return { asset, connector, maskingConnector };
}

async function scheduleLocalMySqlBaseline(baseUrl, assetId, connectorId) {
  const assessmentsResponse = await fetch(`${baseUrl}/api/v1/assessments?limit=100`, {
    headers: developmentHeaders(),
    signal: AbortSignal.timeout(5_000),
  });
  if (!assessmentsResponse.ok) throw new Error("Unable to inspect local MySQL assessments");
  const assessments = await assessmentsResponse.json();
  if (assessments.items.some((item) => item.asset_id === assetId)) return;

  const packsResponse = await fetch(`${baseUrl}/api/v1/control-pack-versions?limit=100`, {
    headers: developmentHeaders(),
    signal: AbortSignal.timeout(5_000),
  });
  if (!packsResponse.ok) throw new Error("Unable to inspect local MySQL control packs");
  const packs = await packsResponse.json();
  const pack = packs.items.find((item) => item.platform === "mysql" && item.status === "active");
  if (!pack) throw new Error("No active MySQL control pack is installed");

  const runKey = "local-mysql-baseline-assessment-v1";
  const response = await fetch(`${baseUrl}/api/v1/assessment-runs`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "idempotency-key": runKey,
      ...developmentHeaders(),
    },
    body: JSON.stringify({
      asset_id: assetId,
      connector_id: connectorId,
      control_pack_version_id: pack.id,
      run_key: runKey,
      max_attempts: 2,
    }),
  });
  if (!response.ok) throw new Error(`Unable to schedule local MySQL baseline: ${response.status}`);
}

async function scheduleLocalMySqlAccessReview(baseUrl, connectorId) {
  const day = new Date().toISOString().slice(0, 10);
  const deduplicationKey = `local-mysql-access-review-${day}`;
  const jobsResponse = await fetch(`${baseUrl}/api/v1/scan-jobs?limit=100`, {
    headers: developmentHeaders(),
    signal: AbortSignal.timeout(5_000),
  });
  if (!jobsResponse.ok) throw new Error("Unable to inspect local access-review jobs");
  const jobs = await jobsResponse.json();
  if (jobs.items.some((item) => item.deduplication_key === deduplicationKey)) return;
  const response = await fetch(`${baseUrl}/api/v1/scan-jobs`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "idempotency-key": deduplicationKey,
      ...developmentHeaders(),
    },
    body: JSON.stringify({
      connector_id: connectorId,
      assessment_id: null,
      job_type: "access_review",
      deduplication_key: deduplicationKey,
      payload: {
        probe_ids: ["mysql.account_context", "mysql.account_privileges"],
        schemas: [],
        metadata: {
          mode: "collector_account_only",
          reads_row_values: false,
        },
      },
      max_attempts: 2,
    }),
  });
  if (!response.ok) {
    throw new Error(`Unable to schedule local MySQL access review: ${response.status}`);
  }
}

async function ensureLocalMySqlMaskingPolicy(baseUrl, source) {
  const name = `${source.database} local masking plan`;
  const policiesResponse = await fetch(`${baseUrl}/api/v1/masking-policies?limit=100`, {
    headers: developmentHeaders(),
    signal: AbortSignal.timeout(5_000),
  });
  if (!policiesResponse.ok) throw new Error("Unable to inspect local masking policies");
  const policies = await policiesResponse.json();
  if (policies.items.some((item) => item.name === name && item.version === 1)) return;
  const response = await fetch(`${baseUrl}/api/v1/masking-policies`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      // This is desired-state bootstrap. A fresh key permits safe recreation if a
      // local policy was deliberately removed while an old replay record remains.
      "idempotency-key": `local-mysql-masking-plan-${Date.now().toString(36)}`,
      ...developmentHeaders(),
    },
    body: JSON.stringify({
      name,
      version: 1,
      classification: "Restricted and confidential",
      strategy: "substitute",
      target_environment: "development",
      parameters: {
        datasets: source.table_count,
        source_asset: source.database,
      },
    }),
  });
  if (!response.ok) {
    throw new Error(`Unable to create local MySQL masking plan: ${response.status}`);
  }
  const created = await response.json();
  if (created.name !== name || created.version !== 1 || created.parameters?.workflow_status !== "draft") {
    throw new Error("Local MySQL masking plan bootstrap returned an unexpected record");
  }
}

async function scheduleLocalMySqlDiscovery(baseUrl, connectorId) {
  const day = new Date().toISOString().slice(0, 10);
  const deduplicationKey = `local-mysql-column-discovery-${day}`;
  const jobsResponse = await fetch(`${baseUrl}/api/v1/scan-jobs?limit=100`, {
    headers: developmentHeaders(),
    signal: AbortSignal.timeout(5_000),
  });
  if (!jobsResponse.ok) throw new Error("Unable to inspect local discovery jobs");
  const jobs = await jobsResponse.json();
  if (jobs.items.some((item) => item.deduplication_key === deduplicationKey)) return;
  const response = await fetch(`${baseUrl}/api/v1/scan-jobs`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "idempotency-key": deduplicationKey,
      ...developmentHeaders(),
    },
    body: JSON.stringify({
      connector_id: connectorId,
      assessment_id: null,
      job_type: "classification",
      deduplication_key: deduplicationKey,
      payload: {
        probe_ids: ["mysql.column_inventory"],
        schemas: [],
        metadata: { mode: "metadata_only", reads_row_values: false },
      },
      max_attempts: 2,
    }),
  });
  if (!response.ok) {
    throw new Error(`Unable to schedule local MySQL discovery: ${response.status}`);
  }
}

function environmentWithoutAzureSql(source) {
  return Object.fromEntries(
    Object.entries(source).filter(([name]) => !name.toUpperCase().startsWith("AZURE_SQL_")),
  );
}

function startLocalMySqlCollector(source) {
  return spawn(python, ["-m", "assurance_collector.main", "run"], {
    cwd: join(repositoryRoot, "services", "collector"),
    stdio: "inherit",
    env: {
      ...apiEnvironment,
      PYTHONUNBUFFERED: "1",
      COLLECTOR_ENVIRONMENT: "development",
      COLLECTOR_API_URL: apiBaseUrl,
      COLLECTOR_COLLECTOR_ID: "local-mysql-collector",
      COLLECTOR_TENANT_ID: LOCAL_SYNTHETIC_TENANT_ID,
      COLLECTOR_CREDENTIAL_ROOT: source.credential_root,
      COLLECTOR_LIVENESS_FILE: join(source.credential_root, "collector-live"),
      COLLECTOR_ENABLE_LEASING: "true",
      COLLECTOR_METRICS_PORT: "9465",
    },
  });
}

function startLocalMySqlMasker(source) {
  return spawn(python, ["-m", "assurance_collector.local_masker", "run"], {
    cwd: join(repositoryRoot, "services", "collector"),
    stdio: "inherit",
    env: {
      ...localMaskerSystemEnvironment(),
      PYTHONUNBUFFERED: "1",
      LOCAL_MASKER_API_URL: apiBaseUrl,
      LOCAL_MASKER_COLLECTOR_ID: "local-mysql-masker",
      LOCAL_MASKER_TENANT_ID: LOCAL_SYNTHETIC_TENANT_ID,
      LOCAL_MASKER_HOST: source.host,
      LOCAL_MASKER_PORT: String(source.port),
      LOCAL_MASKER_SOURCE_DATABASE: source.database,
      LOCAL_MASKER_TARGET_PREFIX: source.target_database_prefix,
      LOCAL_MASKER_STAGING_PREFIX: source.staging_database_prefix,
      LOCAL_MASKER_CREDENTIAL_ROOT: source.credential_root,
      LOCAL_MASKER_SOURCE_SECRET_FILE: source.secret_file,
      LOCAL_MASKER_TARGET_SECRET_FILE: source.target_secret_file,
      LOCAL_MASKER_KEY_FILE: source.masking_key_file,
    },
  });
}

function localMaskerSystemEnvironment() {
  const approved = {};
  for (const name of [
    "ComSpec",
    "LANG",
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "TEMP",
    "TMP",
    "TMPDIR",
    "WINDIR",
  ]) {
    const value = process.env[name];
    if (typeof value === "string" && value) approved[name] = value;
  }
  return approved;
}

async function waitForApi(baseUrl, child) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error("The local API stopped during startup");
    try {
      const response = await fetch(`${baseUrl}/health/ready`, {
        signal: AbortSignal.timeout(1_000),
      });
      if (response.ok && (await response.json()).status === "ok") return;
    } catch {
      // Expected while uvicorn and the database initialize.
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250));
  }
  throw new Error("The local API did not become ready within 30 seconds");
}

async function seedControlPacks(baseUrl) {
  const existingResponse = await fetch(`${baseUrl}/api/v1/control-pack-versions?limit=100`, {
    headers: developmentHeaders(),
    signal: AbortSignal.timeout(5_000),
  });
  if (!existingResponse.ok) {
    const detail = (await existingResponse.text()).slice(0, 500);
    throw new Error(`Unable to inspect existing control packs: ${existingResponse.status} ${detail}`);
  }
  const existing = await existingResponse.json();
  const installed = new Set(
    (Array.isArray(existing.items) ? existing.items : []).map(
      (pack) => `${String(pack.pack_id)}\0${String(pack.version)}`,
    ),
  );
  const manifest = JSON.parse(
    readFileSync(join(repositoryRoot, "control-packs", "manifest.json"), "utf8"),
  );
  for (const entry of manifest.packs) {
    const raw = readFileSync(join(repositoryRoot, "control-packs", ...entry.path.split("/")));
    const pack = JSON.parse(raw.toString("utf8"));
    if (installed.has(`${pack.pack_id}\0${pack.version}`)) continue;
    const payload = {
      schema_version: pack.schema_version,
      pack_id: pack.pack_id,
      version: pack.version,
      platform: pack.platform,
      title: pack.title,
      description: pack.description,
      status: pack.release.status,
      released_at: pack.release.released_at,
      supersedes: pack.release.supersedes,
      immutable: pack.release.immutable,
      controls: pack.controls.map((control) => ({
        control_id: control.id,
        domain: control.domain,
        title: control.title,
        objective: control.objective,
        severity: control.severity,
        environments: control.applicability.environments,
        version_scope: control.applicability.version_scope,
        applicability_notes: control.applicability.notes,
        assessment_mode: control.assessment.mode,
        probe_ids: control.assessment.probe_ids,
        decision_mode: control.assessment.decision_mode,
        manual_evidence_requirements: control.assessment.manual_evidence_requirements,
        allowed_fields: control.evidence.allowed_fields,
        limitations: control.limitations,
        remediation_guidance: control.remediation.guidance,
      })),
    };
    const digest = createHash("sha256").update(raw).digest("hex").slice(0, 24);
    const response = await fetch(`${baseUrl}/api/v1/control-pack-versions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "idempotency-key": `local-pack-${digest}`,
        ...developmentHeaders(),
      },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const detail = (await response.text()).slice(0, 500);
      throw new Error(`Unable to seed ${pack.pack_id} ${pack.version}: ${response.status} ${detail}`);
    }
  }
}

function developmentHeaders() {
  return {
    "x-tenant-id": LOCAL_SYNTHETIC_TENANT_ID,
    "x-subject": "local-bootstrap",
    "x-roles": "admin",
  };
}

function collectorHeaders(subject) {
  return {
    "x-tenant-id": LOCAL_SYNTHETIC_TENANT_ID,
    "x-subject": subject,
    "x-roles": "collector",
  };
}

function stopWithError(message) {
  console.error(message);
  stop(1);
}

function stop(code) {
  if (stopping) return;
  stopping = true;
  for (const child of children) child.kill("SIGTERM");
  setTimeout(() => process.exit(code), 250).unref();
}
