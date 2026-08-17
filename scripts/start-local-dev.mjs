import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const vinextCli = fileURLToPath(
  new URL("../node_modules/vinext/dist/cli.js", import.meta.url),
);

const child = spawn(
  process.execPath,
  [vinextCli, "dev", ...process.argv.slice(2)],
  {
    stdio: "inherit",
    env: {
      ...process.env,
      DEPLOYMENT_ENVIRONMENT: "development",
      CONSOLE_AUTH_MODE: "development",
      ALLOW_INSECURE_CONSOLE_AUTH: "true",
      CONSOLE_DATA_MODE: process.env.CONSOLE_DATA_MODE ?? "fixture",
      CONSOLE_DEVELOPMENT_EMAIL:
        process.env.CONSOLE_DEVELOPMENT_EMAIL ?? "developer@localhost.invalid",
    },
  },
);

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => child.kill(signal));
}

child.on("error", (error) => {
  console.error(`Unable to start the local website: ${error.message}`);
  process.exitCode = 1;
});

child.on("exit", (code, signal) => {
  process.exitCode = signal ? 1 : (code ?? 1);
});
