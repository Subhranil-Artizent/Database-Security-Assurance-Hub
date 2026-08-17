import vinext from "vinext";
import { defineConfig } from "vite";
import hostingConfig from "./.openai/hosting.json" with { type: "json" };
import { sites } from "./build/sites-vite-plugin.ts";
import { resolveLocalConsoleAuth } from "./scripts/local-console-auth.mjs";
import { resolveLocalSyntheticCollection } from "./scripts/local-synthetic-collection.mjs";

const SITE_CREATOR_PLACEHOLDER_DATABASE_ID =
  "00000000-0000-4000-8000-000000000000";

const { d1, r2 } = hostingConfig;

type ConsoleDataMode = "api" | "fixture";

function resolveConsoleDataMode(
  command: string,
  mode: string,
  environment: NodeJS.ProcessEnv,
): ConsoleDataMode {
  const requested = environment.CONSOLE_DATA_MODE?.trim().toLowerCase();
  if (requested && requested !== "api" && requested !== "fixture") {
    throw new Error("CONSOLE_DATA_MODE must be either 'api' or 'fixture'");
  }

  const resolved = (requested ?? "api") as ConsoleDataMode;
  if (resolved === "fixture" && (command !== "serve" || mode !== "development")) {
    throw new Error("Fixture console data is restricted to the local development server");
  }
  return resolved;
}

// macOS Seatbelt blocks FSEvents, so Codex previews need polling for HMR.
const isCodexSeatbeltSandbox = process.env.CODEX_SANDBOX === "seatbelt";

const localBindingConfig = {
  main: "./worker/index.ts",
  compatibility_flags: ["nodejs_compat"],
  d1_databases: d1
    ? [
        {
          binding: d1,
          database_name: "site-creator-d1",
          database_id: SITE_CREATOR_PLACEHOLDER_DATABASE_ID,
        },
      ]
    : [],
  r2_buckets: r2
    ? [
        {
          binding: r2,
          bucket_name: "site-creator-r2",
        },
      ]
    : [],
};

export default defineConfig(async ({ command, mode }) => {
  const localConsoleAuth = resolveLocalConsoleAuth({
    command,
    mode,
    environment: process.env,
  });
  const consoleDataMode = resolveConsoleDataMode(command, mode, process.env);
  const assuranceApiBaseUrl = process.env.ASSURANCE_API_BASE_URL?.trim() ?? "";
  const localSyntheticCollection = resolveLocalSyntheticCollection({
    command,
    mode,
    environment: process.env,
    localConsoleAuth,
    consoleDataMode,
    apiBaseUrl: assuranceApiBaseUrl,
  });
  const localMySqlMode = process.env.AEGISDB_LOCAL_MYSQL_MODE?.trim().toLowerCase() === "true";

  // Keep Wrangler and Miniflare state project-local. These are non-secret tool
  // settings; application environment belongs in ignored `.env*` files.
  process.env.WRANGLER_WRITE_LOGS ??= "false";
  process.env.WRANGLER_LOG_PATH ??= ".wrangler/logs";
  process.env.MINIFLARE_REGISTRY_PATH ??= ".wrangler/registry";

  // Wrangler snapshots its log path while the Cloudflare plugin is imported.
  const { cloudflare } = await import("@cloudflare/vite-plugin");

  return {
    define: {
      __AEGISDB_LOCAL_CONSOLE_AUTH__: JSON.stringify(localConsoleAuth.enabled),
      __AEGISDB_LOCAL_CONSOLE_EMAIL__: JSON.stringify(localConsoleAuth.email),
      __AEGISDB_LOCAL_CONSOLE_TENANT_ID__: JSON.stringify(
        localConsoleAuth.tenantId,
      ),
      __AEGISDB_LOCAL_CONSOLE_ROLES__: JSON.stringify(localConsoleAuth.roles),
      __AEGISDB_CONSOLE_DATA_MODE__: JSON.stringify(consoleDataMode),
      __AEGISDB_ASSURANCE_API_BASE_URL__: JSON.stringify(assuranceApiBaseUrl),
      __AEGISDB_LOCAL_SYNTHETIC_COLLECTION__: JSON.stringify(
        localSyntheticCollection,
      ),
      __AEGISDB_LOCAL_MYSQL_MODE__: JSON.stringify(localMySqlMode),
    },
    server: isCodexSeatbeltSandbox
      ? { watch: { useFsEvents: false, usePolling: true } }
      : undefined,
    plugins: [
      vinext(),
      sites(),
      cloudflare({
        viteEnvironment: { name: "rsc", childEnvironments: ["ssr"] },
        config: localBindingConfig,
      }),
    ],
  };
});
