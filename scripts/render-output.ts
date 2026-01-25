const args = process.argv.slice(2);

type Options = {
  baseUrl: string;
  chain: string;
  collection: string;
  start: number;
  count: number;
  tokens: string[];
  concurrency: number;
  width?: string;
  format: string;
  cache?: string;
  fresh: boolean;
  outputDir: string;
  timeoutMs: number;
};

const defaults: Options = {
  baseUrl: "http://127.0.0.1:8080",
  chain: "base",
  collection: "",
  start: 1,
  count: 25,
  tokens: [],
  concurrency: 6,
  width: "512",
  format: "png",
  cache: undefined,
  fresh: false,
  outputDir: "",
  timeoutMs: 30000,
};

function usage() {
  console.log(`
Usage:
  bun run scripts/render-output.ts --collection 0x... --output-dir ./outputs [options]

Options:
  --base-url       Base URL (default: http://127.0.0.1:8080)
  --chain          Chain name (default: base)
  --collection     Collection address (required)
  --start          Start token id (default: 1)
  --count          Number of tokens (default: 25)
  --tokens         Comma-separated token ids (overrides start/count)
  --concurrency    Concurrent requests (default: 6)
  --width          Width preset or numeric (default: 512)
  --format         webp | png | jpg | jpeg (default: png)
  --cache          Cache timestamp param (optional)
  --fresh          Send fresh=1
  --output-dir     Directory for image output (required)
  --timeout-ms     Request timeout in ms (default: 30000)
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
      case "--output-dir":
        opts.outputDir = input[++i] ?? opts.outputDir;
        break;
      case "--timeout-ms":
        opts.timeoutMs = parseInt(input[++i] ?? `${opts.timeoutMs}`, 10);
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

async function ensureDir(path: string) {
  const { mkdir } = await import("node:fs/promises");
  await mkdir(path, { recursive: true });
}

function filenameForToken(opts: Options, tokenId: string) {
  return `${opts.chain}-${opts.collection}-${tokenId}.${opts.format}`;
}

async function main() {
  const opts = parseArgs(args);
  if (!opts.collection) {
    console.error("Missing --collection");
    usage();
    process.exit(1);
  }
  if (!opts.outputDir) {
    console.error("Missing --output-dir");
    usage();
    process.exit(1);
  }
    if (
      Number.isNaN(opts.start) ||
      Number.isNaN(opts.count) ||
      Number.isNaN(opts.concurrency) ||
      Number.isNaN(opts.timeoutMs)
    ) {
    console.error("Invalid numeric option");
    process.exit(1);
  }

  await ensureDir(opts.outputDir);

  const tokens =
    opts.tokens.length > 0
      ? opts.tokens
      : Array.from({ length: opts.count }, (_, idx) => `${opts.start + idx}`);

  let index = 0;
  let failures = 0;
  const failureDetails: string[] = [];

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

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), opts.timeoutMs);
    try {
      const response = await fetch(url.toString(), {
        redirect: "follow",
        signal: controller.signal,
      });
      if (!response.ok) {
        failures += 1;
        failureDetails.push(`${tokenId}: HTTP ${response.status}`);
        return;
      }
      const buffer = new Uint8Array(await response.arrayBuffer());
      const outPath = `${opts.outputDir}/${filenameForToken(opts, tokenId)}`;
      await Bun.write(outPath, buffer);
    } catch (err) {
      failures += 1;
      failureDetails.push(`${tokenId}: ${(err as Error).message}`);
    } finally {
      clearTimeout(timeout);
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

  console.log(`Render output completed: ${tokens.length - failures}/${tokens.length} saved`);
  if (failureDetails.length > 0) {
    console.log("Failures:");
    for (const detail of failureDetails) {
      console.log(`- ${detail}`);
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
