import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Boots the REAL API process against the disposable fixture database, exactly
 * as the production acceptance suites boot the real image against theirs: the
 * shipped entry point, the real configuration validator and the real restricted
 * role connections. Nothing is stubbed, monkey-patched or intercepted.
 *
 * It binds loopback on an ephemeral port, the payment family is explicitly
 * enabled (it ships DEFAULT OFF, and enabling it requires authentication,
 * commerce sessions, actions, grants and a dedicated restricted database), and
 * every line the process writes is kept IN MEMORY for the leak canary. No log
 * file is written.
 */

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE_FLAG = "OPENARC_COMMERCE_PAYMENT_FIXTURE";

export interface ApiStack {
  readonly baseUrl: string;
  /** Everything the API process wrote. Memory only. */
  logs(): string;
  stop(): Promise<void>;
}

function operatorSecret(): string {
  return randomBytes(32).toString("base64url");
}

async function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("PORT_UNAVAILABLE"));
        return;
      }
      const { port } = address;
      server.close(() => resolvePort(port));
    });
  });
}

export async function startApi(): Promise<ApiStack> {
  if (process.env[FIXTURE_FLAG] !== "1") throw new Error("FIXTURE_DISABLED");
  const fixture = await import("../packages/db/test/postgres-fixture.js");
  const entry = resolve(ROOT, "apps/api/dist/server.js");
  if (!existsSync(entry)) throw new Error("API_BUILD_MISSING");

  const port = await freePort();
  const child = spawn(process.execPath, [entry], {
    cwd: ROOT,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      PATH: process.env["PATH"] ?? "",
      NODE_ENV: "test",
      HOST: "127.0.0.1",
      PORT: String(port),
      APP_ORIGIN: "http://localhost:5183",
      COMMIT_SHA: "0123456789abcdef0123456789abcdef01234567",
      AUTH_ENABLED: "true",
      AUTH_DATABASE_URL: fixture.appUrl(),
      AUTH_SECRET: operatorSecret(),
      AUTH_RP_ID: "localhost",
      TENANT_DATABASE_URL: fixture.tenantUrl(),
      // The four families the payment family requires, and nothing else.
      COMMERCE_SESSIONS_ENABLED: "true",
      COMMERCE_ACTIONS_ENABLED: "true",
      COMMERCE_GRANTS_ENABLED: "true",
      COMMERCE_PAYMENTS_ENABLED: "true",
    },
  });

  const lines: string[] = [];
  child.stdout?.on("data", (chunk: Buffer) => lines.push(chunk.toString("utf8")));
  child.stderr?.on("data", (chunk: Buffer) => lines.push(chunk.toString("utf8")));

  let exited: number | null = null;
  child.once("exit", (code) => {
    exited = code ?? 0;
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 30_000;
  for (;;) {
    if (exited !== null) throw new Error("API_EXITED_DURING_STARTUP");
    try {
      const response = await fetch(`${baseUrl}/v2/public/payment-capabilities`, {
        signal: AbortSignal.timeout(2_000),
      });
      if (response.status < 500) {
        await response.text();
        break;
      }
    } catch {
      // Not listening yet.
    }
    if (Date.now() > deadline) throw new Error("API_STARTUP_TIMEOUT");
    await new Promise((sleep) => setTimeout(sleep, 200));
  }

  return {
    baseUrl,
    logs: () => lines.join(""),
    stop: async () => {
      if (exited !== null) return;
      child.kill("SIGTERM");
      await new Promise<void>((done) => {
        const timer = setTimeout(() => {
          child.kill("SIGKILL");
          done();
        }, 5_000);
        child.once("exit", () => {
          clearTimeout(timer);
          done();
        });
      });
    },
  };
}
