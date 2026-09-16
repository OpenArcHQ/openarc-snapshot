import {
  SettlementLiveModeUnsupportedError,
  parseSettlementConfig,
  parseWorkerConfig,
} from './config.js';
import { startWorkerRuntime } from './runtime.js';

/**
 * Bounded tenant notification worker entry point.
 *
 * LIMITATION: this process consumes durable tenant mutation notifications and,
 * when the settlement observation family is explicitly enabled, observes
 * durable payment attempts through a loopback lookup transport. It does not
 * execute payments, materialize projections, send notifications, call
 * providers, sign or broadcast, reconcile evidence or require Redis.
 *
 * Disabled exits cleanly without opening a database connection. Enabled exits
 * non-zero on initialization failure; SIGINT/SIGTERM trigger graceful shutdown
 * with signal-handler cleanup and a bounded pool close.
 *
 * The settlement observation family ships DEFAULT OFF. Requesting its live
 * mode exits non-zero with the P04-07 prerequisites: there is no live
 * transport in this build.
 */
async function main(): Promise<void> {
  const config = parseWorkerConfig(process.env);
  // Parsed for its refusals even when the worker itself is disabled, so an
  // operator who asks for live settlement observation is told so immediately
  // instead of starting a process that silently observes nothing.
  parseSettlementConfig(process.env);
  if (!config.enabled) return;
  const runtime = startWorkerRuntime({ config });
  // A signal during startup leaves ready pending by design; settle on either
  // the ready barrier or the stopped barrier so a graceful stop never hangs.
  await Promise.race([runtime.ready, runtime.stopped]);
  await runtime.stopped;
}

main().then(
  () => {
    process.exitCode = 0;
  },
  (error: unknown) => {
    if (error instanceof SettlementLiveModeUnsupportedError) {
      // Fixed, non-echoing refusal. It carries no URL, credential or host.
      process.stderr.write(`${error.message}\n`);
    }
    process.exitCode = 1;
  },
);
