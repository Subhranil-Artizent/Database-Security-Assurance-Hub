import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
process.env.ASSURANCE_LOCAL_MYSQL_ENV_FILE ??= resolve(repositoryRoot, "..", "Database", ".env");
process.env.ASSURANCE_LOCAL_DATABASE_URL ??= "sqlite+aiosqlite:///./assurance-mysql-local.db";
process.env.ASSURANCE_SEED_DEMO_DATA ??= "false";
await import("./start-local-stack.mjs");
