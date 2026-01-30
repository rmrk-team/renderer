import { mkdir, readFile, writeFile } from "node:fs/promises";
import net from "node:net";
import path from "node:path";

type TokenConfig = {
  label: string;
  chain: string;
  collection: string;
  tokenId: string;
  assetId?: string;
};

type BenchmarkConfig = {
  baseUrl?: string;
  format?: string;
  width?: string;
  tokens: TokenConfig[];
};

type Sample = {
  label: string;
  chain: string;
  collection: string;
  tokenId: string;
  assetId?: string;
  url: string;
  durationMs: number;
  status: number;
  bytes: number;
  result?: string;
  fallback?: string;
  fallbackReason?: string;
  complete?: string;
  errorCode?: string;
  rendererError?: string;
  error?: string;
};

type IterationResult = {
  index: number;
  sampleCount: number;
  trimmedCount: number;
  medianMs: number;
  p95Ms: number;
  statusCounts: Record<string, number>;
  resultCounts: Record<string, number>;
  fallbackCounts: Record<string, number>;
  errorCodeCounts: Record<string, number>;
  rendererErrorCounts: Record<string, number>;
  samples: Sample[];
};

type ModeResult = {
  mode: string;
  warmupIterations: number;
  iterations: IterationResult[];
  overallMedianMs: number;
  iterationMedianMs: number;
  tokenMedians: Record<string, number>;
  logPath: string;
};

type RunRecord = {
  runId: string;
  timestamp: string;
  commit: string;
  dirty: boolean;
  configPath: string;
  baseUrl: string;
  port: number;
  format: string;
  width: string;
  iterations: number;
  concurrency: number;
  trimRatio: number;
  timeoutMs: number;
  rustLog: string;
  modes: Record<string, ModeResult>;
};

const args = process.argv.slice(2);
const repoRoot = path.resolve(import.meta.dir, "..");
const defaultConfigPath = path.join(repoRoot, "benchmarks", "renderer-benchmark-config.json");
const defaultResultsPath = path.join(repoRoot, "benchmarks", "renderer-benchmarks.json");

const defaults = {
  configPath: defaultConfigPath,
  resultsPath: defaultResultsPath,
  baseUrl: "",
  port: 8086,
  portProvided: false,
  baseUrlProvided: false,
  format: "",
  width: "",
  iterations: 3,
  concurrency: 3,
  trimRatio: 0.1,
  timeoutMs: 60000,
  rustLog: "proj_renderer=debug,sqlx=warn",
  modes: ["fresh", "cached", "pinned"],
};

function usage() {
  console.log(`
Usage:
  bun run scripts/renderer-benchmark.ts [options]

Options:
  --config        Path to benchmark config JSON
  --results       Path to results JSON
  --base-url      Base URL for renderer (default: http://127.0.0.1:<port>)
  --port          Port for renderer (default: 8086)
  --format        Override output format (default: config)
  --width         Override width preset (default: config)
  --iterations    Iterations per mode (default: 3)
  --concurrency   Concurrent requests (default: 3)
  --trim          Outlier trim ratio (default: 0.1)
  --timeout-ms    Request timeout in ms (default: 60000)
  --rust-log      RUST_LOG value (default: debug)
  --modes         Comma-separated modes: fresh,cached,pinned
  --help          Show help
`.trim());
}

function parseArgs(input: string[]) {
  const opts = { ...defaults };
  for (let i = 0; i < input.length; i += 1) {
    const arg = input[i];
    switch (arg) {
      case "--config":
        opts.configPath = input[++i] ?? opts.configPath;
        break;
      case "--results":
        opts.resultsPath = input[++i] ?? opts.resultsPath;
        break;
      case "--base-url":
        opts.baseUrl = input[++i] ?? opts.baseUrl;
        opts.baseUrlProvided = true;
        break;
      case "--port":
        opts.port = Number(input[++i] ?? opts.port);
        opts.portProvided = true;
        break;
      case "--format":
        opts.format = input[++i] ?? opts.format;
        break;
      case "--width":
        opts.width = input[++i] ?? opts.width;
        break;
      case "--iterations":
        opts.iterations = Number(input[++i] ?? opts.iterations);
        break;
      case "--concurrency":
        opts.concurrency = Number(input[++i] ?? opts.concurrency);
        break;
      case "--trim":
        opts.trimRatio = Number(input[++i] ?? opts.trimRatio);
        break;
      case "--timeout-ms":
        opts.timeoutMs = Number(input[++i] ?? opts.timeoutMs);
        break;
      case "--rust-log":
        opts.rustLog = input[++i] ?? opts.rustLog;
        break;
      case "--modes":
        opts.modes = (input[++i] ?? "")
          .split(",")
          .map((value) => value.trim())
          .filter(Boolean);
        break;
      case "--help":
        usage();
        process.exit(0);
      default:
        if (arg.startsWith("--")) {
          console.warn(`Unknown option: ${arg}`);
        }
    }
  }
  return opts;
}

async function isPortAvailable(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once("error", () => resolve(false));
    server.once("listening", () => {
      server.close(() => resolve(true));
    });
    server.listen(port, "127.0.0.1");
  });
}

async function findAvailablePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address && typeof address !== "string") {
        const { port } = address;
        server.close(() => resolve(port));
      } else {
        server.close(() => reject(new Error("failed to acquire port")));
      }
    });
  });
}

async function loadEnvFile(filePath: string): Promise<Record<string, string>> {
  const env: Record<string, string> = {};
  try {
    const raw = await readFile(filePath, "utf8");
    const lines = raw.split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) {
        continue;
      }
      const eq = trimmed.indexOf("=");
      if (eq === -1) {
        continue;
      }
      const key = trimmed.slice(0, eq).trim();
      let value = trimmed.slice(eq + 1).trim();
      if (
        (value.startsWith("'") && value.endsWith("'")) ||
        (value.startsWith('"') && value.endsWith('"'))
      ) {
        value = value.slice(1, -1);
      }
      env[key] = value;
    }
  } catch {
    return env;
  }
  return env;
}

async function readJson<T>(filePath: string, fallback: T): Promise<T> {
  try {
    const raw = await readFile(filePath, "utf8");
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function median(values: number[]): number {
  if (values.length === 0) {
    return 0;
  }
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) {
    return (sorted[mid - 1] + sorted[mid]) / 2;
  }
  return sorted[mid];
}

function percentile(values: number[], pct: number): number {
  if (values.length === 0) {
    return 0;
  }
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.ceil((pct / 100) * sorted.length) - 1);
  return sorted[idx] ?? 0;
}

function trimOutliers(values: number[], ratio: number): number[] {
  if (values.length === 0) {
    return [];
  }
  const sorted = [...values].sort((a, b) => a - b);
  const trim = Math.floor(sorted.length * ratio);
  if (trim * 2 >= sorted.length) {
    return sorted;
  }
  return sorted.slice(trim, sorted.length - trim);
}

function countBy(values: Array<string | undefined>): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) {
    const key = value ?? "none";
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runGit(cmd: string[]): Promise<string> {
  const proc = Bun.spawn(cmd, {
    cwd: repoRoot,
    stdout: "pipe",
    stderr: "pipe",
  });
  const output = await new Response(proc.stdout).text();
  const code = await proc.exited;
  if (code !== 0) {
    const err = await new Response(proc.stderr).text();
    throw new Error(`git ${cmd.join(" ")} failed: ${err}`);
  }
  return output.trim();
}

async function gitInfo() {
  const commit = await runGit(["git", "rev-parse", "HEAD"]);
  const dirty = (await runGit(["git", "status", "--porcelain"])).length > 0;
  return { commit, dirty };
}

async function waitForReady(baseUrl: string, timeoutMs: number) {
  const start = Date.now();
  const statusUrl = new URL("/status", baseUrl).toString();
  while (Date.now() - start < timeoutMs) {
    try {
      const response = await fetch(statusUrl);
      if (response.ok) {
        return;
      }
    } catch {
      // ignore
    }
    await sleep(500);
  }
  throw new Error("renderer did not become ready in time");
}

function buildRenderUrl(
  baseUrl: string,
  token: TokenConfig,
  format: string,
  width: string,
  mode: { fresh: boolean; cacheParam?: string },
) {
  const pathSuffix = token.assetId
    ? `/render/${token.chain}/${token.collection}/${token.tokenId}/${token.assetId}/${format}`
    : `/render/${token.chain}/${token.collection}/${token.tokenId}/${format}`;
  const url = new URL(pathSuffix, baseUrl);
  if (width) {
    url.searchParams.set("width", width);
  }
  if (mode.cacheParam) {
    url.searchParams.set("cache", mode.cacheParam);
  }
  if (mode.fresh) {
    url.searchParams.set("fresh", "1");
  }
  return url.toString();
}

async function fetchWithTimeout(url: string, timeoutMs: number) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { redirect: "follow", signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function runIteration(
  tokens: TokenConfig[],
  baseUrl: string,
  format: string,
  width: string,
  mode: { fresh: boolean; cacheParam?: string },
  concurrency: number,
  timeoutMs: number,
): Promise<Sample[]> {
  const samples: Sample[] = [];
  let index = 0;

  async function worker() {
    while (true) {
      const current = index;
      index += 1;
      if (current >= tokens.length) {
        break;
      }
      const token = tokens[current];
      const url = buildRenderUrl(baseUrl, token, format, width, mode);
      const started = Date.now();
      try {
        const response = await fetchWithTimeout(url, timeoutMs);
        const buffer = await response.arrayBuffer();
        samples.push({
          label: token.label,
          chain: token.chain,
          collection: token.collection,
          tokenId: token.tokenId,
          assetId: token.assetId,
          url,
          durationMs: Date.now() - started,
          status: response.status,
          bytes: buffer.byteLength,
          result: response.headers.get("x-renderer-result") ?? undefined,
          fallback: response.headers.get("x-renderer-fallback") ?? undefined,
          fallbackReason: response.headers.get("x-renderer-fallback-reason") ?? undefined,
          complete: response.headers.get("x-renderer-complete") ?? undefined,
          errorCode: response.headers.get("x-renderer-error-code") ?? undefined,
          rendererError: response.headers.get("x-renderer-error") ?? undefined,
        });
      } catch (err) {
        samples.push({
          label: token.label,
          chain: token.chain,
          collection: token.collection,
          tokenId: token.tokenId,
          assetId: token.assetId,
          url,
          durationMs: Date.now() - started,
          status: 0,
          bytes: 0,
          error: (err as Error).message,
        });
      }
    }
  }

  const workers = Array.from({ length: Math.max(1, concurrency) }, () => worker());
  await Promise.all(workers);
  return samples;
}

function summarizeIteration(
  index: number,
  samples: Sample[],
  trimRatio: number,
): IterationResult {
  const durations = samples.map((sample) => sample.durationMs);
  const trimmed = trimOutliers(durations, trimRatio);
  return {
    index,
    sampleCount: durations.length,
    trimmedCount: trimmed.length,
    medianMs: median(trimmed),
    p95Ms: percentile(trimmed, 95),
    statusCounts: countBy(samples.map((sample) => sample.status.toString())),
    resultCounts: countBy(samples.map((sample) => sample.result)),
    fallbackCounts: countBy(samples.map((sample) => sample.fallback)),
    errorCodeCounts: countBy(samples.map((sample) => sample.errorCode)),
    rendererErrorCounts: countBy(samples.map((sample) => sample.rendererError)),
    samples,
  };
}

function tokenMedians(samples: Sample[], trimRatio: number) {
  const grouped = new Map<string, number[]>();
  for (const sample of samples) {
    const list = grouped.get(sample.label) ?? [];
    list.push(sample.durationMs);
    grouped.set(sample.label, list);
  }
  const medians: Record<string, number> = {};
  for (const [label, values] of grouped.entries()) {
    const trimmed = trimOutliers(values, trimRatio);
    medians[label] = median(trimmed);
  }
  return medians;
}

async function runMode(
  modeName: string,
  mode: { fresh: boolean; cacheParam?: string; pinning: boolean; warmupIterations: number },
  options: {
    baseUrl: string;
    format: string;
    width: string;
    tokens: TokenConfig[];
    iterations: number;
    concurrency: number;
    trimRatio: number;
    timeoutMs: number;
    rustLog: string;
    port: number;
    runDir: string;
    envFromFile: Record<string, string>;
  },
) {
  const modeDir = path.join(options.runDir, modeName);
  await mkdir(modeDir, { recursive: true });
  const logPath = path.join(options.runDir, `${modeName}.log`);
  const env = {
    ...process.env,
    ...options.envFromFile,
    HOST: "127.0.0.1",
    PORT: `${options.port}`,
    DB_PATH: path.join(modeDir, "renderer.db"),
    CACHE_DIR: path.join(modeDir, "cache"),
    FALLBACKS_DIR: path.join(modeDir, "fallbacks"),
    PINNED_DIR: path.join(modeDir, "pinned"),
    PINNING_ENABLED: mode.pinning ? "true" : "false",
    LOCAL_IPFS_ENABLED: "false",
    STATUS_PUBLIC: "true",
    FRESH_RATE_LIMIT_SECONDS: "0",
    RUST_LOG: options.rustLog,
  };

  const quotedLogPath = logPath.replace(/"/g, '\\"');
  const proc = Bun.spawn(["bash", "-lc", `cargo run >> "${quotedLogPath}" 2>&1`], {
    cwd: repoRoot,
    env,
  });

  try {
    await waitForReady(options.baseUrl, 30000);
    for (let i = 0; i < mode.warmupIterations; i += 1) {
      await runIteration(
        options.tokens,
        options.baseUrl,
        options.format,
        options.width,
        mode,
        options.concurrency,
        options.timeoutMs,
      );
    }

    const iterations: IterationResult[] = [];
    for (let i = 0; i < options.iterations; i += 1) {
      const samples = await runIteration(
        options.tokens,
        options.baseUrl,
        options.format,
        options.width,
        mode,
        options.concurrency,
        options.timeoutMs,
      );
      iterations.push(summarizeIteration(i + 1, samples, options.trimRatio));
    }

    const allSamples = iterations.flatMap((iteration) => iteration.samples);
    const allDurations = allSamples.map((sample) => sample.durationMs);
    const trimmed = trimOutliers(allDurations, options.trimRatio);
    const overallMedianMs = median(trimmed);
    const iterationMedianMs = median(iterations.map((iteration) => iteration.medianMs));

    return {
      mode: modeName,
      warmupIterations: mode.warmupIterations,
      iterations,
      overallMedianMs,
      iterationMedianMs,
      tokenMedians: tokenMedians(allSamples, options.trimRatio),
      logPath,
    } satisfies ModeResult;
  } finally {
    proc.kill();
    await proc.exited;
  }
}

async function main() {
  const opts = parseArgs(args);
  const config = await readJson<BenchmarkConfig>(opts.configPath, { tokens: [] });
  if (!config.tokens?.length) {
    console.error("No tokens configured; check benchmark config.");
    process.exit(1);
  }

  const { commit, dirty } = await gitInfo();
  const timestamp = new Date().toISOString();
  const runId = `${timestamp.replace(/[:.]/g, "-")}-${commit.slice(0, 7)}`;
  const runDir = path.join(repoRoot, "benchmarks", "runs", runId);
  await mkdir(runDir, { recursive: true });

  let baseUrl =
    opts.baseUrl || config.baseUrl || `http://127.0.0.1:${opts.port}`;
  const parsedBase = new URL(baseUrl);
  let urlPort = Number(parsedBase.port || opts.port);
  if (!opts.baseUrlProvided && !opts.portProvided) {
    urlPort = await findAvailablePort();
    parsedBase.port = `${urlPort}`;
    baseUrl = parsedBase.toString().replace(/\/$/, "");
    console.warn(`Using ephemeral port ${urlPort} for benchmark`);
  } else if (!opts.baseUrlProvided && opts.portProvided) {
    const available = await isPortAvailable(urlPort);
    if (!available) {
      throw new Error(`Port ${urlPort} is already in use`);
    }
  }
  if (!parsedBase.port && opts.port) {
    parsedBase.port = `${opts.port}`;
    baseUrl = parsedBase.toString().replace(/\/$/, "");
  }
  const format = opts.format || config.format || "webp";
  const width = opts.width || config.width || "medium";

  const modes = [
    {
      name: "fresh",
      fresh: true,
      cacheParam: undefined,
      pinning: false,
      warmupIterations: 0,
    },
    {
      name: "cached",
      fresh: false,
      cacheParam: "0",
      pinning: false,
      warmupIterations: 1,
    },
    {
      name: "pinned",
      fresh: false,
      cacheParam: undefined,
      pinning: true,
      warmupIterations: 1,
    },
  ].filter((mode) => opts.modes.includes(mode.name));

  if (modes.length === 0) {
    console.error("No modes selected.");
    process.exit(1);
  }

  const runRecord: RunRecord = {
    runId,
    timestamp,
    commit,
    dirty,
    configPath: path.relative(repoRoot, opts.configPath),
    baseUrl,
    port: urlPort,
    format,
    width,
    iterations: opts.iterations,
    concurrency: opts.concurrency,
    trimRatio: opts.trimRatio,
    timeoutMs: opts.timeoutMs,
    rustLog: opts.rustLog,
    modes: {},
  };

  const envFromFile = await loadEnvFile(path.join(repoRoot, ".env"));

  const collections = new Set(
    config.tokens.map((token) => `${token.chain}:${token.collection}`),
  );
  if (collections.size < 3 || config.tokens.length !== 10) {
    console.warn(
      `Token config is ${config.tokens.length} tokens across ${collections.size} collections.`,
    );
  }
  if (
    !config.tokens.some(
      (token) =>
        token.collection.toLowerCase() ===
          "0x011ff409bc4803ec5cfab41c3fd1db99fd05c004" &&
        token.tokenId === "1",
    )
  ) {
    console.warn("Kanaria token 1 is missing from the benchmark set.");
  }

  for (const mode of modes) {
    console.log(`Running mode: ${mode.name}`);
    const result = await runMode(mode.name, mode, {
      baseUrl,
      format,
      width,
      tokens: config.tokens,
      iterations: opts.iterations,
      concurrency: opts.concurrency,
      trimRatio: opts.trimRatio,
      timeoutMs: opts.timeoutMs,
      rustLog: opts.rustLog,
      port: urlPort,
      runDir,
      envFromFile,
    });
    runRecord.modes[mode.name] = result;
    console.log(
      `- ${mode.name}: median=${result.overallMedianMs.toFixed(1)}ms (iterations median=${result.iterationMedianMs.toFixed(1)}ms)`,
    );
  }

  const existing = await readJson<RunRecord[]>(opts.resultsPath, []);
  existing.push(runRecord);
  await mkdir(path.dirname(opts.resultsPath), { recursive: true });
  await writeFile(opts.resultsPath, JSON.stringify(existing, null, 2));

  console.log(`Saved results to ${path.relative(repoRoot, opts.resultsPath)}`);
}

await main();
