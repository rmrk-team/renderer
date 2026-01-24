const args = process.argv.slice(2);

type Options = {
  baseUrl: string;
  chain: string;
  collection: string;
  start: number;
  count: number;
  concurrency: number;
  width?: string;
  format: string;
  fresh: boolean;
  cache?: string;
  tokens: string[];
};

const defaults: Options = {
  baseUrl: "http://127.0.0.1:8080",
  chain: "base",
  collection: "",
  start: 1,
  count: 25,
  concurrency: 10,
  width: "medium",
  format: "webp",
  fresh: false,
  cache: undefined,
  tokens: [],
};

function usage() {
  console.log(`
Usage:
  bun run scripts/marketplace-sim.ts --collection 0x... [options]

Options:
  --base-url       Base URL (default: http://127.0.0.1:8080)
  --chain          Chain name (default: base)
  --collection     Collection address (required)
  --start          Start token id (default: 1)
  --count          Number of tokens (default: 25)
  --tokens         Comma-separated token ids (overrides start/count)
  --concurrency    Concurrent requests (default: 10)
  --width          Width preset (default: medium)
  --format         webp | png | jpg | jpeg (default: webp)
  --cache          Cache timestamp param (optional)
  --fresh          Send fresh=1
  --help           Show help
`.trim());
}

function parseArgs(input: string[]): Options {
  const opts: Options = { ...defaults };
  for (let i = 0; i < input.length; i += 1) {
    const arg = input[i];
    switch (arg) {
      case "--base-url":
        opts.baseUrl = input[++i] ?? opts.baseUrl;
        break;
      case "--chain":
        opts.chain = input[++i] ?? opts.chain;
        break;
      case "--collection":
        opts.collection = input[++i] ?? opts.collection;
        break;
      case "--start":
        opts.start = parseInt(input[++i] ?? `${opts.start}`, 10);
        break;
      case "--count":
        opts.count = parseInt(input[++i] ?? `${opts.count}`, 10);
        break;
      case "--tokens":
        opts.tokens = (input[++i] ?? "")
          .split(",")
          .map((value) => value.trim())
          .filter(Boolean);
        break;
      case "--concurrency":
        opts.concurrency = parseInt(input[++i] ?? `${opts.concurrency}`, 10);
        break;
      case "--width":
        opts.width = input[++i] ?? opts.width;
        break;
      case "--format":
        opts.format = input[++i] ?? opts.format;
        break;
      case "--cache":
        opts.cache = input[++i] ?? opts.cache;
        break;
      case "--fresh":
        opts.fresh = true;
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

function percentile(values: number[], pct: number): number {
  if (values.length === 0) {
    return 0;
  }
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.ceil((pct / 100) * sorted.length) - 1);
  return sorted[idx] ?? 0;
}

async function main() {
  const opts = parseArgs(args);
  if (!opts.collection) {
    console.error("Missing --collection");
    usage();
    process.exit(1);
  }
  if (Number.isNaN(opts.start) || Number.isNaN(opts.count) || Number.isNaN(opts.concurrency)) {
    console.error("Invalid numeric option");
    process.exit(1);
  }
  const tokens =
    opts.tokens.length > 0
      ? opts.tokens
      : Array.from({ length: opts.count }, (_, idx) => `${opts.start + idx}`);

  const timings: number[] = [];
  const statusCounts = new Map<number, number>();
  const cacheCounts = new Map<string, number>();
  let bytesTotal = 0;
  let failures = 0;

  let index = 0;
  const startTime = Date.now();

  async function fetchToken(tokenId: string) {
    const url = new URL(
      `/render/${opts.chain}/${opts.collection}/${tokenId}/${opts.format}`,
      opts.baseUrl,
    );
    if (opts.width) {
      url.searchParams.set("width", opts.width);
    }
    if (opts.cache) {
      url.searchParams.set("cache", opts.cache);
    }
    if (opts.fresh) {
      url.searchParams.set("fresh", "1");
    }

    const started = Date.now();
    try {
      const response = await fetch(url.toString(), { redirect: "follow" });
      const duration = Date.now() - started;
      timings.push(duration);
      statusCounts.set(response.status, (statusCounts.get(response.status) ?? 0) + 1);

      const cacheHeader = response.headers.get("x-cache") ?? "none";
      cacheCounts.set(cacheHeader, (cacheCounts.get(cacheHeader) ?? 0) + 1);

      const buffer = await response.arrayBuffer();
      bytesTotal += buffer.byteLength;
    } catch (err) {
      failures += 1;
      console.warn(`Request failed for token ${tokenId}: ${(err as Error).message}`);
    }
  }

  async function worker() {
    while (true) {
      const current = index;
      index += 1;
      if (current >= tokens.length) {
        break;
      }
      await fetchToken(tokens[current]);
    }
  }

  const concurrency = Math.max(1, opts.concurrency);
  await Promise.all(Array.from({ length: concurrency }, () => worker()));

  const elapsedSeconds = Math.max(0.001, (Date.now() - startTime) / 1000);
  const total = tokens.length;
  const avg = timings.reduce((sum, value) => sum + value, 0) / Math.max(1, timings.length);

  console.log("Marketplace sim results");
  console.log(`- Requests: ${total} in ${elapsedSeconds.toFixed(2)}s (${(total / elapsedSeconds).toFixed(2)} rps)`);
  console.log(`- Failures: ${failures}`);
  console.log(`- Statuses: ${Array.from(statusCounts.entries())
    .map(([code, count]) => `${code}=${count}`)
    .join(", ") || "none"}`);
  console.log(`- Cache: ${Array.from(cacheCounts.entries())
    .map(([label, count]) => `${label}=${count}`)
    .join(", ") || "none"}`);
  console.log(`- Bytes: ${(bytesTotal / 1024 / 1024).toFixed(2)} MiB`);
  console.log(`- Latency ms: avg=${avg.toFixed(1)} p50=${percentile(timings, 50).toFixed(1)} p95=${percentile(timings, 95).toFixed(1)} p99=${percentile(timings, 99).toFixed(1)}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
