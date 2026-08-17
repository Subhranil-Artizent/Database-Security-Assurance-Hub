import { isAbsolute, relative, resolve } from "node:path";

export const LOCAL_SYNTHETIC_LAUNCH_SOURCE = "npm-dev-integrated-v1";
export const LOCAL_SYNTHETIC_TENANT_ID = "demo-enterprise";
export const LOCAL_SYNTHETIC_COLLECTOR_ID = "demo-collector";

const SQLITE_PREFIX = "sqlite+aiosqlite:///";
const LOCAL_DATABASE_EXTENSIONS = [".db", ".sqlite", ".sqlite3"];

/**
 * Fail closed before the integrated launcher migrates a database or starts a
 * development-authenticated process. The Python helper repeats these checks at
 * its own trust boundary.
 */
export function assertLocalSyntheticCollectionBoundary({
  launchSource,
  apiBaseUrl,
  apiDirectory,
  databaseUrl,
  environment,
  authMode,
  allowInsecureDevAuth,
  tenantId,
  collectorId,
}) {
  if (launchSource !== LOCAL_SYNTHETIC_LAUNCH_SOURCE) {
    throw new Error("Synthetic collection is available only through npm run dev:integrated");
  }
  if (
    environment !== "development" ||
    authMode !== "development" ||
    allowInsecureDevAuth !== "true"
  ) {
    throw new Error("Synthetic collection requires the explicit development authentication boundary");
  }
  if (
    tenantId !== LOCAL_SYNTHETIC_TENANT_ID ||
    collectorId !== LOCAL_SYNTHETIC_COLLECTOR_ID
  ) {
    throw new Error("Synthetic collection is restricted to the seeded demo tenant and collector");
  }

  let parsedApi;
  try {
    parsedApi = new URL(apiBaseUrl);
  } catch {
    throw new Error("Synthetic collection requires a valid loopback API URL");
  }
  if (
    parsedApi.protocol !== "http:" ||
    parsedApi.hostname !== "127.0.0.1" ||
    !parsedApi.port ||
    parsedApi.username ||
    parsedApi.password ||
    parsedApi.pathname !== "/" ||
    parsedApi.search ||
    parsedApi.hash
  ) {
    throw new Error("Synthetic collection requires an uncredentialed 127.0.0.1 HTTP API URL");
  }

  if (!databaseUrl.startsWith(SQLITE_PREFIX) || databaseUrl.includes("?") || databaseUrl.includes("#")) {
    throw new Error("Synthetic collection requires a local sqlite+aiosqlite database");
  }
  let databaseReference;
  try {
    databaseReference = decodeURIComponent(databaseUrl.slice(SQLITE_PREFIX.length));
  } catch {
    throw new Error("Synthetic collection SQLite path is invalid");
  }
  if (!databaseReference || databaseReference === ":memory:" || /[\0\r\n]/.test(databaseReference)) {
    throw new Error("Synthetic collection requires a file-backed local SQLite database");
  }

  const resolvedApiDirectory = resolve(apiDirectory);
  const databasePath = resolve(resolvedApiDirectory, databaseReference);
  const relativeDatabasePath = relative(resolvedApiDirectory, databasePath);
  if (
    !relativeDatabasePath ||
    relativeDatabasePath.startsWith("..") ||
    isAbsolute(relativeDatabasePath) ||
    !LOCAL_DATABASE_EXTENSIONS.some((extension) => databasePath.toLowerCase().endsWith(extension))
  ) {
    throw new Error("Synthetic collection SQLite data must remain inside services/api");
  }

  return Object.freeze({ databasePath });
}

/**
 * Resolve the build-time banner flag. Production builds fail rather than
 * silently accepting a leaked local synthetic-mode flag.
 */
export function resolveLocalSyntheticCollection({
  command,
  mode,
  environment,
  localConsoleAuth,
  consoleDataMode,
  apiBaseUrl,
}) {
  const requested = environment.AEGISDB_LOCAL_SYNTHETIC_COLLECTION?.trim().toLowerCase();
  if (requested === undefined || requested === "false") return false;
  if (requested !== "true") {
    throw new Error("AEGISDB_LOCAL_SYNTHETIC_COLLECTION must be either 'true' or 'false'");
  }

  let parsedApi;
  try {
    parsedApi = new URL(apiBaseUrl);
  } catch {
    throw new Error("Local synthetic collection requires a valid API base URL");
  }
  if (
    command !== "serve" ||
    mode !== "development" ||
    !localConsoleAuth.enabled ||
    localConsoleAuth.tenantId !== LOCAL_SYNTHETIC_TENANT_ID ||
    consoleDataMode !== "api" ||
    parsedApi.protocol !== "http:" ||
    parsedApi.hostname !== "127.0.0.1" ||
    !parsedApi.port
  ) {
    throw new Error("Local synthetic collection cannot be enabled outside dev:integrated");
  }
  return true;
}
