/**
 * Resolve the development-only console identity at Vite configuration time.
 * A production build can never enable this path, even if its environment is
 * accidentally populated with the local development flags.
 */
export function resolveLocalConsoleAuth({ command, mode, environment }) {
  const enabled =
    command === "serve" &&
    mode === "development" &&
    environment.DEPLOYMENT_ENVIRONMENT === "development" &&
    environment.CONSOLE_AUTH_MODE === "development" &&
    environment.ALLOW_INSECURE_CONSOLE_AUTH === "true";

  return {
    enabled,
    email: enabled
      ? (environment.CONSOLE_DEVELOPMENT_EMAIL ?? "developer@localhost.invalid")
      : "",
    tenantId: enabled
      ? safeDevelopmentIdentity(
          environment.AEGISDB_DEVELOPMENT_TENANT_ID,
          "local-development",
        )
      : "",
    roles: enabled
      ? safeDevelopmentIdentity(
          environment.AEGISDB_DEVELOPMENT_ROLES,
          "admin,security_analyst,database_owner",
        )
      : "",
  };
}

function safeDevelopmentIdentity(value, fallback) {
  const normalized = value?.trim() || fallback;
  if (
    normalized.length > 512 ||
    !/^[A-Za-z0-9._,@:-]+$/.test(normalized)
  ) {
    throw new Error("The local console development identity is invalid");
  }
  return normalized;
}
