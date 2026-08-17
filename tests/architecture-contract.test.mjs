import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { resolveLocalConsoleAuth } from "../scripts/local-console-auth.mjs";
import {
  assertLocalSyntheticCollectionBoundary,
  LOCAL_SYNTHETIC_COLLECTOR_ID,
  LOCAL_SYNTHETIC_LAUNCH_SOURCE,
  LOCAL_SYNTHETIC_TENANT_ID,
  resolveLocalSyntheticCollection,
} from "../scripts/local-synthetic-collection.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (...parts) => readFile(path.join(root, ...parts), "utf8");

test("enables synthetic identity only for the explicit local dev launcher", async () => {
  const developmentEnvironment = {
    DEPLOYMENT_ENVIRONMENT: "development",
    CONSOLE_AUTH_MODE: "development",
    ALLOW_INSECURE_CONSOLE_AUTH: "true",
    CONSOLE_DEVELOPMENT_EMAIL: "developer@example.invalid",
  };

  assert.deepEqual(
    resolveLocalConsoleAuth({
      command: "serve",
      mode: "development",
      environment: developmentEnvironment,
    }),
    {
      enabled: true,
      email: "developer@example.invalid",
      tenantId: "local-development",
      roles: "admin,security_analyst,database_owner",
    },
  );
  assert.deepEqual(
    resolveLocalConsoleAuth({
      command: "build",
      mode: "production",
      environment: developmentEnvironment,
    }),
    { enabled: false, email: "", tenantId: "", roles: "" },
    "production builds must stay fail-closed even when local flags are present",
  );
  assert.equal(
    resolveLocalConsoleAuth({
      command: "serve",
      mode: "development",
      environment: {},
    }).enabled,
    false,
    "a plain Vite invocation must not bypass console authentication",
  );
  assert.throws(
    () =>
      resolveLocalConsoleAuth({
        command: "serve",
        mode: "development",
        environment: {
          ...developmentEnvironment,
          AEGISDB_DEVELOPMENT_TENANT_ID: "invalid tenant",
        },
      }),
    /development identity is invalid/,
  );

  const launcher = await read("scripts", "start-local-dev.mjs");
  assert.match(launcher, /DEPLOYMENT_ENVIRONMENT:\s*["']development["']/);
  assert.match(launcher, /CONSOLE_AUTH_MODE:\s*["']development["']/);
  assert.match(launcher, /ALLOW_INSECURE_CONSOLE_AUTH:\s*["']true["']/);
});

test("confines synthetic collection to the integrated loopback SQLite boundary", () => {
  const apiDirectory = path.join(root, "services", "api");
  const safeBoundary = {
    launchSource: LOCAL_SYNTHETIC_LAUNCH_SOURCE,
    apiBaseUrl: "http://127.0.0.1:8000",
    apiDirectory,
    databaseUrl: "sqlite+aiosqlite:///./assurance-local.db",
    environment: "development",
    authMode: "development",
    allowInsecureDevAuth: "true",
    tenantId: LOCAL_SYNTHETIC_TENANT_ID,
    collectorId: LOCAL_SYNTHETIC_COLLECTOR_ID,
  };

  assert.equal(
    assertLocalSyntheticCollectionBoundary(safeBoundary).databasePath,
    path.join(apiDirectory, "assurance-local.db"),
  );
  for (const unsafe of [
    { apiBaseUrl: "https://api.example.com" },
    { databaseUrl: "postgresql+asyncpg://localhost/assurance" },
    { databaseUrl: "sqlite+aiosqlite:///../../outside.db" },
    { environment: "production" },
    { tenantId: "customer-tenant" },
    { collectorId: "customer-collector" },
    { launchSource: "direct-invocation" },
  ]) {
    assert.throws(() => assertLocalSyntheticCollectionBoundary({ ...safeBoundary, ...unsafe }));
  }

  const localConsoleAuth = {
    enabled: true,
    email: "developer@localhost.invalid",
    tenantId: LOCAL_SYNTHETIC_TENANT_ID,
    roles: "admin,security_analyst,database_owner",
  };
  assert.equal(
    resolveLocalSyntheticCollection({
      command: "serve",
      mode: "development",
      environment: { AEGISDB_LOCAL_SYNTHETIC_COLLECTION: "true" },
      localConsoleAuth,
      consoleDataMode: "api",
      apiBaseUrl: "http://127.0.0.1:8000",
    }),
    true,
  );
  assert.throws(() =>
    resolveLocalSyntheticCollection({
      command: "build",
      mode: "production",
      environment: { AEGISDB_LOCAL_SYNTHETIC_COLLECTION: "true" },
      localConsoleAuth,
      consoleDataMode: "api",
      apiBaseUrl: "http://127.0.0.1:8000",
    }),
  );
});

test("keeps synthetic evidence out of every production collector deployment path", async () => {
  const [launcher, helper, consoleShell, collectorDeployment, collectorImage, compose] =
    await Promise.all([
      read("scripts", "start-local-stack.mjs"),
      read("tools", "local_synthetic_collector.py"),
      read("components", "console", "console-shell.tsx"),
      read("infra", "kubernetes", "base", "collector.yaml"),
      read("infra", "docker", "collector.Dockerfile"),
      read("infra", "compose.yaml"),
    ]);

  assert.match(launcher, /tools["'],\s*["']local_synthetic_collector\.py/);
  assert.match(launcher, /AEGISDB_LOCAL_SYNTHETIC_COLLECTION:\s*localMySqlMode\s*\?\s*["']false["']\s*:\s*["']true["']/);
  assert.match(launcher, /DATABASE_MAINTENANCE_URL:\s*["']["']/);
  assert.match(launcher, /OTEL_EXPORTER_OTLP_ENDPOINT:\s*["']["']/);
  assert.match(helper, /JobCompletionRequest/);
  assert.match(helper, /poll_seconds:\s*float\s*=\s*Field\(default=2\.0/);
  assert.match(helper, /outcome=["']collected["']/);
  assert.doesNotMatch(helper, /outcome=["'](?:passed|failed)["']/);
  assert.doesNotMatch(helper, /assessment\.score|["']score["']\s*:/);
  assert.match(
    consoleShell,
    /Synthetic local collection — no customer database queried/,
  );
  assert.match(collectorDeployment, /COLLECTOR_ENABLE_LEASING[\s\S]*value:\s*["']false["']/);
  assert.match(collectorImage, /COLLECTOR_ENABLE_LEASING=false/);
  assert.doesNotMatch(collectorDeployment, /local_synthetic_collector|development_synthetic/);
  assert.doesNotMatch(collectorImage, /local_synthetic_collector|development_synthetic/);
  assert.doesNotMatch(compose, /local_synthetic_collector|development_synthetic/);
});

test("keeps Sites as the only production console identity boundary", async () => {
  const [kustomization, ingress, operationsReadme] = await Promise.all([
    read("infra", "kubernetes", "base", "kustomization.yaml"),
    read("infra", "kubernetes", "base", "ingress.yaml"),
    read("infra", "README.md"),
  ]);

  assert.doesNotMatch(kustomization, /\bweb\.yaml\b/);
  assert.doesNotMatch(ingress, /assurance-hub-web/);
  assert.match(ingress, /path:\s*\/api\/v1/);
  assert.match(operationsReadme, /deployed only through a private Sites deployment/i);
});

test("keeps the bounded image metadata fork available in every web image stage", async () => {
  const dockerfile = await read("infra", "docker", "web.Dockerfile");
  assert.match(dockerfile, /COPY vendor \.\/vendor[\s\S]*npm ci --ignore-scripts/);
  assert.equal(
    (dockerfile.match(/\/workspace\/vendor \.\/vendor/g) ?? []).length,
    2,
  );
});

test("keeps the checked-in base migration frozen and independent of live metadata", async () => {
  const migrationDirectory = path.join(root, "services", "api", "alembic", "versions");
  const migrations = (await readdir(migrationDirectory)).filter((name) => name.endsWith(".py"));
  assert.ok(migrations.length >= 1, "the frozen base migration must remain checked in");
  const contents = await Promise.all(migrations.map((name) => read("services", "api", "alembic", "versions", name)));
  const migration = contents.find((content) => /revision:\s*str\s*=\s*["']20260812_0001["']/.test(content));
  assert.ok(migration, "the frozen 20260812_0001 base migration must remain available");
  assert.doesNotMatch(migration, /Base\.metadata/);
  assert.doesNotMatch(migration, /metadata\.(?:create_all|drop_all)/);
  assert.match(migration, /revision:\s*str\s*=\s*["']20260812_0001["']/);
  assert.match(migration, /down_revision:\s*(?:str\s*\|\s*None\s*=\s*)?None/);
});

test("does not declare application secrets in hosting metadata", async () => {
  const hosting = JSON.parse(await read(".openai", "hosting.json"));
  assert.deepEqual(
    Object.keys(hosting).sort(),
    Object.keys(hosting).filter((key) => ["project_id", "d1", "r2"].includes(key)).sort(),
    "hosting metadata may contain only the Sites project ID and logical bindings",
  );
  assert.equal(hosting.d1, null);
  assert.equal(hosting.r2, null);
  if ("project_id" in hosting) assert.equal(typeof hosting.project_id, "string");
  assert.equal(JSON.stringify(hosting).match(/secret|token|password/gi), null);
});

test("keeps live console configuration explicit and server-side", async () => {
  const [viteConfig, launcher, repository, assetAction, assessmentAction, findingAction, accessAction, maskingAction, maskingWorkflowAction, maskingCopyAction] = await Promise.all([
    read("vite.config.ts"),
    read("scripts", "start-local-dev.mjs"),
    read("components", "console", "repository.ts"),
    read("app", "console", "actions", "assets", "route.ts"),
    read("app", "console", "actions", "assessments", "route.ts"),
    read("app", "console", "actions", "findings", "route.ts"),
    read("app", "console", "actions", "access-reviews", "route.ts"),
    read("app", "console", "actions", "masking-policies", "route.ts"),
    read("app", "console", "actions", "masking-policies", "workflow", "route.ts"),
    read("app", "console", "actions", "masking-policies", "copy", "route.ts"),
  ]);

  assert.match(viteConfig, /requested\s*\?\?\s*["']api["']/);
  assert.match(viteConfig, /resolved\s*===\s*["']fixture["'][\s\S]*command\s*!==\s*["']serve["']/);
  assert.match(launcher, /CONSOLE_DATA_MODE:\s*process\.env\.CONSOLE_DATA_MODE\s*\?\?\s*["']fixture["']/);
  assert.match(viteConfig, /__AEGISDB_ASSURANCE_API_BASE_URL__/);
  assert.match(viteConfig, /__AEGISDB_LOCAL_CONSOLE_TENANT_ID__/);
  assert.match(viteConfig, /__AEGISDB_LOCAL_CONSOLE_ROLES__/);
  assert.doesNotMatch(viteConfig, /AEGISDB_(?:API_BEARER_TOKEN|TOKEN_BROKER_CLIENT_SECRET)/);
  assert.doesNotMatch(repository, /AEGISDB_API_BEARER_TOKEN/);
  assert.match(repository, /process\.env\.AEGISDB_TOKEN_BROKER_URL/);
  assert.match(repository, /process\.env\.AEGISDB_TOKEN_BROKER_CLIENT_ID/);
  assert.match(repository, /process\.env\.AEGISDB_TOKEN_BROKER_CLIENT_SECRET/);
  assert.doesNotMatch(repository, /process\.env\.AEGISDB_DEVELOPMENT_(?:TENANT_ID|ROLES)/);
  assert.match(repository, /getChatGPTUser\(\)/);
  assert.match(repository, /user_id:\s*user\.userId/);
  assert.match(repository, /expiresIn\s*<\s*60\s*\|\|\s*expiresIn\s*>\s*3_600/);
  assert.match(repository, /baseUrl\.username\s*\|\|\s*baseUrl\.password/);
  assert.match(repository, /baseUrl\.protocol\s*!==\s*["']https:["']/);
  assert.match(repository, /authorization:\s*`Bearer \$\{token\}`/);
  assert.match(repository, /redirect:\s*["']manual["']/);
  assert.match(repository, /response\.status\s*>=\s*300\s*&&\s*response\.status\s*<\s*400/);
  assert.doesNotMatch(repository, /redirect:\s*["']error["']/);
  assert.doesNotMatch(repository, /oai-authenticated-user-(?:id|email)/);
  assert.match(repository, /apiMutation\(["']\/assessment-runs["']/);
  assert.doesNotMatch(repository, /apiMutation\(["']\/(?:assessments|scan-jobs)["']/);
  assert.match(repository, /`\/masking-policies\/\$\{encodeURIComponent\(id\)\}\/copy-runs`/);
  assert.match(repository, /requiredString\(job,\s*["']assessment_id["']\)\s*!==\s*assessmentId/);

  for (const action of [assetAction, assessmentAction, findingAction, accessAction, maskingAction, maskingWorkflowAction, maskingCopyAction]) {
    assert.match(action, /requireConsoleMutation\(request\)/);
    assert.match(action, /operationKey\(form\)/);
    assert.doesNotMatch(action, /password|private_key|connection_string|dsn/i);
  }
  for (const maskingSource of [maskingAction, maskingWorkflowAction, maskingCopyAction]) {
    assert.doesNotMatch(maskingSource, /mysql|azure|scan-jobs|probe_ids|endpoint_ref|secret_ref/i);
  }
  assert.doesNotMatch(maskingCopyAction, /\b(?:source_database|target_database|row_cap|host|port|sql)\b/i);
});

test("keeps local MySQL access collection read-only and exposes per-workflow masking boundaries", async () => {
  const [launcher, apiCatalog, collectorCatalog, accessView, maskingView, assessmentView] = await Promise.all([
    read("scripts", "start-local-stack.mjs"),
    read("services", "api", "assurance_hub", "query_catalog.py"),
    read("services", "collector", "assurance_collector", "catalog.py"),
    read("components", "console", "access-view.tsx"),
    read("components", "console", "masking-view.tsx"),
    read("components", "console", "assessments-view.tsx"),
  ]);

  assert.match(launcher, /job_type:\s*["']access_review["']/);
  assert.match(launcher, /environmentWithoutAzureSql\(process\.env\)/);
  assert.match(launcher, /startsWith\(["']AZURE_SQL_["']\)/);
  assert.doesNotMatch(launcher, /\.\.\.process\.env/);
  assert.match(launcher, /probe_ids:\s*\[[\s\S]*mysql\.account_context[\s\S]*mysql\.account_privileges/);
  assert.match(launcher, /reads_row_values:\s*false/);
  assert.match(apiCatalog, /mysql\.account_privileges[\s\S]*SELECT CURRENT_USER\(\)/);
  assert.match(collectorCatalog, /mysql\.account_privileges[\s\S]*SELECT CURRENT_USER\(\)/);
  assert.doesNotMatch(collectorCatalog, /(?:INSERT|UPDATE|DELETE|ALTER|DROP)\s+/i);
  assert.match(accessView, /local collector account only/i);
  assert.match(accessView, /no privileges are changed/i);
  assert.match(maskingView, /Fixed local boundary/i);
  assert.match(maskingView, /source insurance_sample is read-only/i);
  assert.match(maskingView, /Every approved workflow receives its own server-derived local masked database/i);
  assert.match(maskingView, /without overwriting an earlier result/i);
  assert.match(maskingView, /never connects to Azure SQL/i);
  assert.match(maskingView, /500 rows maximum per table/i);
  assert.match(maskingView, /normal assessment collector remains read-only/i);
  assert.match(maskingView, /source and earlier workflow targets are not overwritten/i);
  assert.doesNotMatch(maskingView, /insurance_sample_masked_staging/i);
  assert.doesNotMatch(maskingView, /name=["'](?:source_database|target_database|staging_database|row_cap|host|port|sql|password|credentials?)["']/i);
  assert.match(maskingView, /Start another workflow/i);
  assert.match(maskingView, /Archive workflow/i);
  assert.match(maskingView, /Evidence and the masked target were retained/i);
  assert.match(assessmentView, /local masking-copy proof remains a human-reviewed control/i);
  assert.match(assessmentView, /never passed automatically/i);
});

test("provides a printable management report without database controls or secrets", async () => {
  const [report, printButton, navigation] = await Promise.all([
    read("components", "console", "report-view.tsx"),
    read("components", "console", "print-report-button.tsx"),
    read("components", "console", "console-navigation.tsx"),
  ]);
  assert.match(navigation, /\/console\/report/);
  assert.match(report, /Passed ÷ \(Passed \+ Failed\) × 100/);
  assert.match(report, /Azure SQL is not used by this local workflow/);
  assert.match(report, /controlled local assurance implementation, not a certification/i);
  assert.match(printButton, /window\.print\(\)/);
  assert.doesNotMatch(report + printButton, /name=["'](?:host|port|sql|password|credentials?|connection_string)["']/i);
});

test("isolates repeatable per-workflow local masking from standard and production collectors", async () => {
  const [launcher, masker, maskingEngine, standardClient, bootstrap, collectorDeployment, collectorImage, compose] =
    await Promise.all([
      read("scripts", "start-local-stack.mjs"),
      read("services", "collector", "assurance_collector", "local_masker.py"),
      read("services", "collector", "assurance_collector", "masking_engine.py"),
      read("services", "collector", "assurance_collector", "api_client.py"),
      read("tools", "bootstrap_local_mysql.py"),
      read("infra", "kubernetes", "base", "collector.yaml"),
      read("infra", "docker", "collector.Dockerfile"),
      read("infra", "compose.yaml"),
    ]);
  const maskerLaunch = launcher.slice(
    launcher.indexOf("function startLocalMySqlMasker"),
    launcher.indexOf("async function waitForApi"),
  );
  const sourceAdapter = masker.slice(
    masker.indexOf("class MySqlSourceReader"),
    masker.indexOf("class MySqlTargetWriter"),
  );
  const targetWriter = masker.slice(
    masker.indexOf("class MySqlTargetWriter"),
    masker.indexOf("def execute_local_masking_copy"),
  );
  const publish = targetWriter.slice(
    targetWriter.indexOf("    def publish"),
    targetWriter.indexOf("    def read_final_snapshot"),
  );
  const publishRecovery = targetWriter.slice(
    targetWriter.indexOf("    def _recover_publish_after_error"),
  );
  const maskingExecution = masker.slice(
    masker.indexOf("def execute_local_masking_copy"),
    masker.indexOf("class LocalMaskingApiClient"),
  );
  const stagingCleanup = masker.slice(
    masker.indexOf("def _require_staging_cleanup_safe"),
    masker.indexOf("def _acquire_publish_lock"),
  );

  assert.match(masker, /supported_job_types["']:\s*\[["']masking_copy["']\]/);
  assert.match(masker, /"probe_results": \[\],[\s\S]*"summary": result\.as_summary\(\)/);
  assert.match(masker, /consistent_snapshot=True[\s\S]*readonly=True/);
  assert.match(masker, /source_before_hmac[\s\S]*source_after_hmac/);
  assert.match(masker, /target_manifest_hmac[\s\S]*foreign_keys_valid/);
  assert.doesNotMatch(sourceAdapter, /\b(?:INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE)\b/);
  assert.doesNotMatch(masker, /\b(?:UPDATE|DELETE|TRUNCATE)\b/);
  assert.doesNotMatch(standardClient, /masking_copy/);

  assert.match(maskingEngine, /if not column\.sensitive[\s\S]*masked_row\.append\(value\)[\s\S]*masked = mappings[\s\S]*masked_row\.append\(masked\)/);
  const transformationIndex = maskingExecution.indexOf("transformation = mask_snapshot(");
  const stageIndex = maskingExecution.indexOf("target.stage(transformation.target)");
  assert.ok(transformationIndex >= 0, "masking transformation must be present");
  assert.ok(stageIndex >= 0, "staging insert must be present");
  assert.ok(
    transformationIndex < stageIndex,
    "selected sensitive values must be transformed before the first target insert",
  );

  assert.match(maskerLaunch, /assurance_collector\.local_masker["'],\s*["']run/);
  assert.match(maskerLaunch, /LOCAL_MASKER_SOURCE_SECRET_FILE:\s*source\.secret_file/);
  assert.match(maskerLaunch, /LOCAL_MASKER_TARGET_SECRET_FILE:\s*source\.target_secret_file/);
  assert.match(maskerLaunch, /LOCAL_MASKER_KEY_FILE:\s*source\.masking_key_file/);
  assert.match(maskerLaunch, /LOCAL_MASKER_TARGET_PREFIX:\s*source\.target_database_prefix/);
  assert.match(maskerLaunch, /LOCAL_MASKER_STAGING_PREFIX:\s*source\.staging_database_prefix/);
  assert.doesNotMatch(maskerLaunch, /\.\.\.(?:process\.env|apiEnvironment)/);
  assert.match(launcher, /secret_ref:\s*source\.target_writer_secret_ref/);
  assert.match(launcher, /collector_id:\s*["']local-mysql-masker["']/);
  assert.match(launcher, /capabilities:\s*\[["']masking_copy["']\]/);

  assert.match(bootstrap, /function load_local_mysql_values|def load_local_mysql_values/);
  assert.match(bootstrap, /TARGET_WRITER_PRIVILEGES/);
  assert.match(bootstrap, /STAGING_WRITER_PRIVILEGES/);
  assert.match(bootstrap, /TARGET_READER_USERNAME\s*=\s*["']insurance_masked_test_ro["']/);
  assert.match(bootstrap, /TARGET_READER_PRIVILEGES\s*=\s*\{[\s\S]*"SELECT"[\s\S]*"SHOW VIEW"[\s\S]*\}/);
  assert.match(bootstrap, /FINAL_GRANT_DATABASE_PATTERN:\s*TARGET_READER_PRIVILEGES/);
  assert.match(launcher, /source\.target_reader_account\s*!==\s*["']insurance_masked_test_ro["']/);
  assert.match(launcher, /source\.target_reader_secret_file/);
  assert.match(bootstrap, /STAGING_DATABASE_PREFIX\s*=\s*["']aegisdb_mask_stage_["']/);
  assert.match(bootstrap, /SHOW GRANTS FOR CURRENT_USER/);
  assert.match(masker, /TARGET_WRITER_PRIVILEGES\s*=\s*frozenset\(\{"CREATE", "INSERT", "SELECT"\}\)/);
  assert.match(masker, /STAGING_WRITER_PRIVILEGES\s*=\s*frozenset\([\s\S]*"DROP"[\s\S]*"REFERENCES"[\s\S]*\)/);
  assert.match(stagingCleanup, /_require_staging_cleanup_safe[\s\S]*issubset\(expected_by_name\)[\s\S]*_stable_create_statement[\s\S]*staging table differs from the expected manifest/);
  assert.match(stagingCleanup, /_clean_staging_base_tables[\s\S]*_qualified\(database, table_name\)[\s\S]*f"DROP TABLE \{tables\}"/);
  assert.match(masker, /SELECT GET_LOCK\(%s, 0\)/);
  assert.match(publish, /renames = ", "\.join\([\s\S]*_qualified\(self\._staging_database[\s\S]*_qualified\(self\._target_database[\s\S]*f"RENAME TABLE \{renames\}"/);
  assert.match(publishRecovery, /staging_inventory\.completely_empty and not final_inventory\.completely_empty[\s\S]*_read_expected_snapshot\([\s\S]*self\._target_database[\s\S]*_foreign_keys_valid\([\s\S]*self\._target_database[\s\S]*return True/);
  assert.match(publishRecovery, /if final_inventory\.completely_empty[\s\S]*_verify_target_manifest\([\s\S]*self\._staging_database[\s\S]*f"RENAME TABLE \{renames\}"[\s\S]*_schema_inventory\([\s\S]*self\._staging_database[\s\S]*completely_empty[\s\S]*return False/);
  assert.match(targetWriter, /if not staging_inventory\.completely_empty:[\s\S]*staging must be empty when recovering a published target/);
  assert.match(maskingExecution, /existing = target\.read_existing_final\(transformation\.target, ROW_CAP\)[\s\S]*existing_hmac = validated_target_hmac\(existing, transformation\.target\)/);
  assert.match(maskingExecution, /not counts_match or not hmac\.compare_digest\(expected_hmac, observed_hmac\)[\s\S]*observed target differs from the deterministic copy/);
  for (const localOnlySource of [masker, maskerLaunch, bootstrap]) {
    assert.doesNotMatch(localOnlySource, /AZURE_SQL|database\.windows\.net/i);
  }
  for (const productionPath of [collectorDeployment, collectorImage, compose]) {
    assert.doesNotMatch(productionPath, /local_masker|local-mysql-masker/);
  }
  assert.match(maskingEngine, /TARGET_DATABASE_PREFIX\s*=\s*["']insurance_sample_masked_["']/);
  assert.match(maskingEngine, /STAGING_DATABASE_PREFIX\s*=\s*["']aegisdb_mask_stage_["']/);
  assert.match(maskingEngine, /staging_database_for_target/);
});

test("documents repeatable per-workflow local masking without implying production approval", async () => {
  const [readme, architecture, environment, implementation, threatModel, checklist, runbook] =
    await Promise.all([
      read("README.md"),
      read("docs", "architecture.md"),
      read("docs", "environment.md"),
      read("docs", "implementation-status.md"),
      read("docs", "threat-model.md"),
      read("docs", "phased-acceptance-checklist.md"),
      read("docs", "runbook.md"),
    ]);

  assert.match(readme, /npm run dev:mysql/);
  assert.match(readme, /server-derived target named `insurance_sample_masked_<workflow>`/i);
  assert.match(readme, /no more\s+than 500 rows\s+per table/i);
  assert.match(readme, /Selected sensitive values are\s+transformed before any target insert/i);
  assert.match(readme, /non-sensitive keys and structural fields\s+may be retained/i);
  assert.match(readme, /Raw rows\s+and values never enter the Hub API, evidence, logs, or browser/i);
  assert.match(readme, /`aegisdb_mask_stage_<workflow>`/);
  assert.match(readme, /drop stale staging tables only when\s+they match the exact worker-owned manifest/i);
  assert.match(readme, /one atomic rename/i);
  assert.match(readme, /never runs `DROP`, `UPDATE`, `DELETE`, or overwrite operations on the source or\s+final database/i);
  assert.match(readme, /Each new workflow gets a different empty final database/i);
  assert.match(readme, /interrupted completion may recover only its own target/i);
  assert.match(readme, /changed\s+source, mismatched target, or ambiguous final\/staging state fails closed/i);
  assert.match(readme, /never\s+mark a control passed and never assign a\s+score/i);
  assert.match(readme, /never\s+connects to or changes Azure SQL/i);

  assert.match(architecture, /Development-only local MySQL masking proof/);
  assert.match(architecture, /Raw rows and values never enter the Hub API, evidence, logs, or browser/i);
  assert.match(architecture, /one\s+atomic multi-table rename publishes the complete copy/i);
  assert.match(architecture, /changed source, mismatched final, or ambiguous\s+final\/staging state fails closed/i);
  assert.match(architecture, /never pass a control and never calculate an\s+assurance score/i);
  assert.match(environment, /Internal staging \| Paired `aegisdb_mask_stage_<workflow>`/);
  assert.match(environment, /Existing final \| A new workflow receives a new empty target/);
  assert.match(environment, /`DROP` is available only for staging\s+cleanup/i);
  assert.match(implementation, /The local proof is excluded from the standard collector, production images,\s+Compose, and Kubernetes/i);
  assert.match(implementation, /changed source,\s+mismatch, or ambiguous final\/staging state fails closed/i);
  assert.match(threatModel, /staging-only `DROP` after exact worker-manifest and DDL checks/i);
  assert.match(threatModel, /every new workflow gets an empty final/i);
  assert.match(checklist, /The fixed local proof is never promoted and does not satisfy this\s+gate/i);
  assert.match(checklist, /Automated\s+evidence still requires mandatory human review and cannot pass or score a\s+control/i);
  assert.match(runbook, /Azure\s+SQL configuration is ignored and Azure SQL is never\s+connected/i);
  assert.match(runbook, /Do not bypass a final-state check, truncate a final database, or add an\s+overwrite flag/i);
  assert.match(runbook, /only exact\s+staging cleanup may use `DROP`/i);

  const combined = [readme, architecture, environment, implementation, threatModel, checklist, runbook].join("\n");
  assert.doesNotMatch(combined, /No masking executor exists|no source masking executor exists/i);
  assert.doesNotMatch(combined, /raw (?:source and transformed )?values (?:remain|exist)[^\n]*inside/i);
  assert.doesNotMatch(combined, /raw values confined to the worker/i);
});

test("documents the per-user live console token exchange and fail-closed secrets", async () => {
  const environmentDoc = await read("docs", "environment.md");
  assert.match(environmentDoc, /AEGISDB_TOKEN_BROKER_URL/);
  assert.match(environmentDoc, /AEGISDB_TOKEN_BROKER_CLIENT_ID/);
  assert.match(environmentDoc, /AEGISDB_TOKEN_BROKER_CLIENT_SECRET/);
  assert.match(environmentDoc, /never accepts a shared production API bearer token/i);
  assert.match(environmentDoc, /fail closed/i);
});

test("keeps live console joins complete, bounded, and honest about pending scores", async () => {
  const [repository, dataModel, assessmentView, compose, webDockerfile] = await Promise.all([
    read("components", "console", "repository.ts"),
    read("components", "console", "data.ts"),
    read("components", "console", "assessments-view.tsx"),
    read("infra", "compose.yaml"),
    read("infra", "docker", "web.Dockerfile"),
  ]);

  assert.match(repository, /const MAX_JOIN_ROWS = 10_000/);
  assert.match(repository, /apiAllPages\(["']\/assets["']\)/);
  assert.match(repository, /apiAllPages\(["']\/findings["']\)/);
  assert.match(repository, /apiAllPages\(["']\/assessments["']\)/);
  assert.match(repository, /seenCursors\.has\(next\)/);
  assert.match(repository, /getAssessmentActionOptions\(\)/);
  assert.match(repository, /apiAllPages\(["']\/connectors["']\)/);
  assert.match(repository, /apiAllPages\(["']\/control-pack-versions["']\)/);
  assert.match(assessmentView, /repository\.getAssessmentActionOptions\(\)/);
  assert.doesNotMatch(assessmentView, /get(?:Assets|Connectors|ControlPacks)\(\{\s*limit:\s*100/);
  assert.match(repository, /status === ["']queued["']/);
  assert.match(
    repository,
    /status === ["']running["'] && collectionStatus !== ["']review_required["']/,
  );
  assert.match(
    repository,
    /collectionStatus === ["']review_required["'][\s\S]*["']Pending["']/,
  );
  assert.match(dataModel, /score: number \| null/);
  assert.match(dataModel, /ControlStatus = [^;]+["']Pending["']/);
  assert.match(assessmentView, /Not scored/);
  assert.doesNotMatch(compose, /^\s{2}web:\s*$/m);
  assert.doesNotMatch(compose, /assurance-hub-web/);
  assert.doesNotMatch(compose, /PUBLIC_API_BASE_URL/);
  assert.match(webDockerfile, /ARG ASSURANCE_API_BASE_URL/);
  assert.match(webDockerfile, /ARG CONSOLE_DATA_MODE=api/);
  assert.doesNotMatch(webDockerfile, /ALLOW_INSECURE_CONSOLE_AUTH/);
});

test("derives and revalidates assessment targets on the server", async () => {
  const [repository, assessmentView, assessmentAction] = await Promise.all([
    read("components", "console", "repository.ts"),
    read("components", "console", "assessments-view.tsx"),
    read("app", "console", "actions", "assessments", "route.ts"),
  ]);

  assert.match(repository, /function buildAssessmentTargets\(/);
  assert.match(repository, /connector\.assetId/);
  assert.match(repository, /connector\.status !== ["']Online["']/);
  assert.match(repository, /connector\.capabilities\?\.includes\(["']read_only_metadata["']\)/);
  assert.match(repository, /connector\.platform !== asset\.platform/);
  assert.match(repository, /pack\.status !== ["']active["']/);
  assert.match(repository, /activePacksByPlatform\.get\(asset\.platform\)/);
  assert.match(repository, /targets\.length >= MAX_JOIN_ROWS/);
  assert.match(repository, /startAssessmentTarget\(targetId/);
  assert.match(repository, /await this\.getAssessmentActionOptions\(\)/);
  assert.match(repository, /candidate\.id === targetId/);

  assert.match(assessmentView, /actionOptions\.targets\.map/);
  assert.match(assessmentView, /name=["']assessment_target["']/);
  assert.doesNotMatch(
    assessmentView,
    /name=["'](?:asset_id|connector_id|control_pack_version_id)["']/,
  );
  assert.match(assessmentView, /Run a synthetic local assessment/);
  assert.match(assessmentView, /Queue synthetic collection/);

  assert.match(assessmentAction, /startAssessmentTarget\(/);
  assert.match(assessmentAction, /formText\(form, ["']assessment_target["']/);
  assert.doesNotMatch(
    assessmentAction,
    /formText\(form, ["'](?:asset_id|connector_id|control_pack_version_id)["']/,
  );
});

test("bounds every upstream response body before parsing", async () => {
  const repository = await read("components", "console", "repository.ts");
  const brokerExchange = repository.slice(
    repository.indexOf("async function exchangeUserToken"),
    repository.indexOf("function secureRuntimeUrl"),
  );

  assert.match(repository, /const MAX_RESPONSE_BYTES = 2 \* 1024 \* 1024/);
  assert.match(repository, /const MAX_BROKER_RESPONSE_BYTES = 32 \* 1024/);
  assert.match(repository, /const MAX_ERROR_RESPONSE_BYTES = 64 \* 1024/);
  assert.match(repository, /headers\.get\(["']content-length["']\)/);
  assert.match(repository, /response\.body\.getReader\(\)/);
  assert.match(repository, /receivedBytes > maximumBytes/);
  assert.match(repository, /await reader\.cancel\(\)/);
  assert.match(repository, /new TextDecoder\(["']utf-8["'], \{ fatal: true \}\)/);
  assert.doesNotMatch(repository, /response\.(?:text|json)\(\)/);
  assert.match(brokerExchange, /response\.status >= 300 && response\.status < 400/);
  assert.match(brokerExchange, /unsafe redirect/i);
  assert.ok(
    brokerExchange.indexOf("readBoundedResponseBody") < brokerExchange.indexOf("clearTimeout(timer)"),
    "the token broker timeout must cover bounded response body consumption",
  );
});

test("preserves terminal finding dispositions without bypassing governed decisions", async () => {
  const [repository, dataModel, findingsView, findingAction] = await Promise.all([
    read("components", "console", "repository.ts"),
    read("components", "console", "data.ts"),
    read("components", "console", "findings-view.tsx"),
    read("app", "console", "actions", "findings", "route.ts"),
  ]);

  assert.match(dataModel, /FindingStatus[^;]+["']False positive["']/);
  assert.match(repository, /["']False positive["']:\s*["']false_positive["']/);
  assert.match(repository, /value\s*===\s*["']false_positive["']\)\s*return\s*["']False positive["']/);
  assert.match(findingsView, /<option>False positive<\/option>/);
  assert.match(findingsView, /isEditableFindingStatus\(finding\.status\)/);
  assert.match(findingsView, /separate exception request, independent approval, and revocation workflow/i);
  assert.doesNotMatch(findingAction, /["']risk_accepted["']/);
  assert.doesNotMatch(findingAction, /["']false_positive["']/);
});

test("keeps assessment review decisions explicit, bounded, and server-scored", async () => {
  const [
    dataModel,
    repository,
    assessmentList,
    reviewView,
    reviewPage,
    decisionAction,
    finalizeAction,
  ] = await Promise.all([
    read("components", "console", "data.ts"),
    read("components", "console", "repository.ts"),
    read("components", "console", "assessments-view.tsx"),
    read("components", "console", "assessment-review-view.tsx"),
    read("app", "console", "assessments", "[assessmentId]", "page.tsx"),
    read("app", "console", "actions", "assessments", "control-decision", "route.ts"),
    read("app", "console", "actions", "assessments", "finalize", "route.ts"),
  ]);

  assert.match(dataModel, /ReviewOutcome\s*=\s*["']passed["']\s*\|\s*["']failed["']\s*\|\s*["']not_applicable["']/);
  assert.match(repository, /getAssessmentReview\(assessmentId:/);
  assert.match(repository, /\/assessments\/\$\{encodeURIComponent\(id\)\}\/review/);
  assert.match(repository, /\/control-decisions\/\$\{encodeURIComponent\(definitionId\)\}/);
  assert.match(repository, /\{ outcome: input\.outcome, rationale: input\.rationale \}/);
  assert.match(repository, /idempotencyKey,\s*["']PUT["']/);
  assert.match(repository, /\/assessments\/\$\{encodeURIComponent\(id\)\}\/finalize/);
  assert.match(repository, /\{ confirmation: ["']finalize["'] \}/);

  assert.match(assessmentList, /\/console\/assessments\/\$\{encodeURIComponent\(assessment\.id\)\}/);
  assert.match(reviewPage, /<AssessmentReviewView assessmentId=\{assessmentId\}/);
  assert.match(reviewView, /action=["']\/console\/actions\/assessments\/control-decision["']/);
  assert.match(reviewView, /action=["']\/console\/actions\/assessments\/finalize["']/);
  assert.match(reviewView, /Score = passed ÷ \(passed \+ failed\) × 100/);
  assert.match(reviewView, /browser never submits one/i);
  assert.doesNotMatch(reviewView, /name=["'](?:score|reviewer|source_endpoint|sql|password|credentials?)["']/i);

  for (const action of [decisionAction, finalizeAction]) {
    assert.match(action, /requireConsoleMutation\(request\)/);
    assert.match(action, /exactForm\(form, FIELDS\)/);
    assert.match(action, /operationKey\(form\)/);
    assert.doesNotMatch(action, /\b(?:score|reviewer|source_endpoint|sql|password|credentials?)\b/i);
  }
  assert.match(
    decisionAction,
    /formEnum\(form, ["']outcome["'], \[["']passed["'], ["']failed["'], ["']not_applicable["']\] as const\)/,
  );
  assert.match(finalizeAction, /formEnum\(form, ["']confirmation["'], \[["']finalize["']\] as const\)/);
});
