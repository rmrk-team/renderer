import { JsonRpcProvider, Contract, Interface } from "ethers";

type CatalogPart = {
  index: number;
  itemType: number;
  z: number;
  metadataUri: string;
};

type FetchResult = {
  ok: boolean;
  status?: number;
  gateway?: string;
  error?: string;
  timeout?: boolean;
  attempts?: AttemptInfo[];
};

type AttemptInfo = {
  gateway: string;
  status?: number;
  timeout?: boolean;
  error?: string;
  bytes?: number;
};

type JsonFetchResult = {
  data?: Record<string, unknown>;
  error?: string;
  gateway?: string;
  status?: number;
  timeout?: boolean;
  attempts?: AttemptInfo[];
};

const DEFAULT_GATEWAYS = [
  "https://rmrk.myfilebase.com/ipfs/",
  "https://cloudflare-ipfs.com/ipfs/",
  "https://ipfs.io/ipfs/",
  "https://dweb.link/ipfs/",
  "https://nftstorage.link/ipfs/",
  "https://w3s.link/ipfs/",
];

const CATALOG_ABI = [
  "function getTotalParts() view returns (uint64)",
  "function getPaginatedPartIds(uint256 start,uint256 limit) view returns (uint64[])",
  "function getPart(uint64 partId) view returns (tuple(uint8 itemType,uint8 z,address[] equippable,string metadataURI))",
  "function getPartByIndex(uint256 index) view returns (tuple(uint8 itemType,uint8 z,address[] equippable,string metadataURI))",
];
const LOG_EVENT_ABI = [
  "event AddedPart(uint64 indexed partId,uint8 indexed itemType,uint8 zIndex,address[] equippableAddresses,string metadataURI)",
];

const CATALOG_ADDRESS =
  process.env.CATALOG_ADDRESS ??
  "0x6aa04fbaa07e3a3f548cb0ae04b5e32c0a5fcfa9";
const CATALOG_CHAIN = (process.env.CATALOG_CHAIN ?? process.env.CHAIN ?? "").trim();
const RPC_URL = resolveRpcUrl();
const TIMEOUT_SECONDS = Number(process.env.IPFS_TIMEOUT_SECONDS ?? "8");
const CONCURRENCY = Number(process.env.AUDIT_CONCURRENCY ?? "4");
const LOG_RANGE = Number(process.env.LOG_RANGE ?? "10000");
const IPFS_JSON_MAX_BYTES = Number(
  process.env.IPFS_JSON_MAX_BYTES ?? String(2 * 1024 * 1024),
);

function resolveRpcUrl(): string {
  const direct = process.env.RPC_URL?.trim();
  if (direct) {
    return direct;
  }
  const endpoints = parseRpcEndpoints();
  if (CATALOG_CHAIN && endpoints[CATALOG_CHAIN]?.length) {
    return endpoints[CATALOG_CHAIN][0];
  }
  const entries = Object.entries(endpoints).filter(([, urls]) => urls.length > 0);
  if (!CATALOG_CHAIN && entries.length === 1) {
    return entries[0][1][0];
  }
  throw new Error(
    "RPC endpoint not configured. Set RPC_URL or CATALOG_CHAIN with RPC_ENDPOINTS.",
  );
}

function parseRpcEndpoints(): Record<string, string[]> {
  const raw = process.env.RPC_ENDPOINTS;
  if (!raw) {
    return {};
  }
  const parsed = safeParseJson<Record<string, string[]>>(raw);
  if (!parsed) {
    return {};
  }
  return Object.fromEntries(
    Object.entries(parsed).map(([key, urls]) => [
      key,
      Array.isArray(urls) ? urls.filter((url) => typeof url === "string") : [],
    ]),
  );
}

function parseGateways(): string[] {
  const raw = process.env.IPFS_GATEWAYS;
  const gateways = raw ? safeParseJson<string[]>(raw) ?? [] : [];
  const merged = [...gateways, ...DEFAULT_GATEWAYS];
  const seen = new Set<string>();
  return merged.filter((item) => {
    const trimmed = item.trim();
    if (!trimmed) {
      return false;
    }
    if (seen.has(trimmed)) {
      return false;
    }
    seen.add(trimmed);
    return true;
  });
}

function safeParseJson<T>(value: string): T | null {
  try {
    return JSON.parse(value) as T;
  } catch {
    return null;
  }
}

function parseIpfsUri(uri: string): { cid: string; path: string } | null {
  const trimmed = uri.trim();
  if (!trimmed.startsWith("ipfs://")) {
    return null;
  }
  let rest = trimmed.slice("ipfs://".length);
  if (rest.startsWith("ipfs/")) {
    rest = rest.slice("ipfs/".length);
  }
  const [cid, ...pathParts] = rest.split("/");
  if (!cid) {
    return null;
  }
  return { cid, path: pathParts.join("/") };
}

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

function isTimeoutError(err: unknown) {
  if (err instanceof Error && err.name === "AbortError") {
    return true;
  }
  return false;
}

async function readJsonWithLimit(
  response: Response,
  maxBytes: number,
): Promise<{ data?: Record<string, unknown>; error?: string; bytes?: number }> {
  const contentLength = response.headers.get("content-length");
  if (contentLength) {
    const length = Number(contentLength);
    if (!Number.isNaN(length) && length > maxBytes) {
      return { error: "json_too_large", bytes: length };
    }
  }
  if (!response.body) {
    return { error: "empty_body" };
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    if (value) {
      total += value.length;
      if (total > maxBytes) {
        await reader.cancel();
        return { error: "json_too_large", bytes: total };
      }
      chunks.push(value);
    }
  }
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }
  try {
    const text = new TextDecoder().decode(combined);
    return { data: JSON.parse(text) as Record<string, unknown>, bytes: total };
  } catch (err) {
    return { error: `json_parse_failed:${String(err)}`, bytes: total };
  }
}

async function fetchIpfsJson(
  uri: string,
  gateways: string[],
  timeoutMs: number,
): Promise<JsonFetchResult> {
  const parsed = parseIpfsUri(uri);
  if (!parsed) {
    return { error: "not_ipfs" };
  }
  const suffix = parsed.path ? `/${parsed.path}` : "";
  const attempts: AttemptInfo[] = [];
  for (const gateway of gateways) {
    const url = `${gateway}${parsed.cid}${suffix}`;
    try {
      const response = await fetchWithTimeout(url, {}, timeoutMs);
      if (!response.ok) {
        attempts.push({ gateway, status: response.status });
        continue;
      }
      const parsedJson = await readJsonWithLimit(response, IPFS_JSON_MAX_BYTES);
      if (!parsedJson.data) {
        attempts.push({
          gateway,
          status: response.status,
          error: parsedJson.error,
          bytes: parsedJson.bytes,
        });
        continue;
      }
      return {
        data: parsedJson.data,
        gateway,
        status: response.status,
        attempts,
      };
    } catch (err) {
      attempts.push({
        gateway,
        error: String(err),
        timeout: isTimeoutError(err),
      });
    }
  }
  return { error: "fetch_failed", attempts };
}

async function probeIpfsAsset(
  uri: string,
  gateways: string[],
  timeoutMs: number,
): Promise<FetchResult> {
  const parsed = parseIpfsUri(uri);
  if (!parsed) {
    return { ok: false, error: "not_ipfs" };
  }
  const suffix = parsed.path ? `/${parsed.path}` : "";
  const attempts: AttemptInfo[] = [];
  for (const gateway of gateways) {
    const url = `${gateway}${parsed.cid}${suffix}`;
    try {
      const response = await fetchWithTimeout(
        url,
        { headers: { Range: "bytes=0-0" } },
        timeoutMs,
      );
      attempts.push({ gateway, status: response.status });
      if (response.status === 200 || response.status === 206) {
        return { ok: true, status: response.status, gateway, attempts };
      }
    } catch (err) {
      attempts.push({
        gateway,
        error: String(err),
        timeout: isTimeoutError(err),
      });
    }
  }
  return { ok: false, error: "fetch_failed", attempts };
}

async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = [];
  let index = 0;
  async function worker() {
    while (index < items.length) {
      const current = index++;
      results[current] = await fn(items[current]);
    }
  }
  const workers = Array.from({ length: Math.max(1, limit) }, () => worker());
  await Promise.all(workers);
  return results;
}

function pickAssetUri(meta: Record<string, unknown>): string | null {
  const candidates = [
    meta.mediaUri,
    meta.image,
    meta.imageUri,
    meta.animation_url,
  ];
  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.trim()) {
      return candidate.trim();
    }
  }
  return null;
}

async function main() {
  const gateways = parseGateways();
  const timeoutMs = TIMEOUT_SECONDS * 1000;
  const provider = new JsonRpcProvider(RPC_URL);
  const contract = new Contract(CATALOG_ADDRESS, CATALOG_ABI, provider);
  let parts: CatalogPart[] = [];
  const errors: unknown[] = [];
  try {
    const total: bigint = await contract.getTotalParts();
    parts = await mapWithConcurrency(
      Array.from({ length: Number(total) }, (_, index) => index),
      CONCURRENCY,
      async (index) => {
        const part = await contract.getPartByIndex(index);
        const metadataUri = part.metadataURI ?? part[3];
        return {
          index,
          itemType: Number(part.itemType ?? part[0]),
          z: Number(part.z ?? part[1]),
          metadataUri: String(metadataUri ?? ""),
        } as CatalogPart;
      },
    );
  } catch (err) {
    errors.push(err);
  }

  if (parts.length === 0) {
    try {
      const pageSize = Number(process.env.PART_PAGE_SIZE ?? "200");
      const partIds: bigint[] = [];
      let start = 0;
      while (true) {
        const batch: bigint[] = await contract.getPaginatedPartIds(
          start,
          pageSize,
        );
        if (batch.length === 0) {
          break;
        }
        partIds.push(...batch);
        if (batch.length < pageSize) {
          break;
        }
        start += pageSize;
      }
      parts = await mapWithConcurrency(partIds, CONCURRENCY, async (partId) => {
        const part = await contract.getPart(partId);
        const metadataUri = part.metadataURI ?? part[3];
        return {
          index: Number(partId),
          itemType: Number(part.itemType ?? part[0]),
          z: Number(part.z ?? part[1]),
          metadataUri: String(metadataUri ?? ""),
        } as CatalogPart;
      });
    } catch (err) {
      errors.push(err);
    }
  }

  if (parts.length === 0) {
    const iface = new Interface(LOG_EVENT_ABI);
    const event = iface.getEvent("AddedPart");
    if (!event) {
      throw errors[0];
    }
    const topic = event.topicHash;
    const fromBlock = Number(process.env.FROM_BLOCK ?? "0");
    const latest = Number(await provider.getBlockNumber());
    const toBlock = Number(process.env.TO_BLOCK ?? String(latest));
    const partsById = new Map<string, CatalogPart>();
    let start = fromBlock;
    let segment = 0;
    while (start <= toBlock) {
      const end = Math.min(start + LOG_RANGE - 1, toBlock);
      const logs = await provider.getLogs({
        address: CATALOG_ADDRESS,
        topics: [topic],
        fromBlock: start,
        toBlock: end,
      });
      for (const log of logs) {
        const decoded = iface.parseLog(log);
        if (!decoded) {
          continue;
        }
        const partId = decoded.args.partId?.toString() ?? "";
        const metadataUri = decoded.args.metadataURI ?? "";
        if (!partId) {
          continue;
        }
        partsById.set(partId, {
          index: Number(partId),
          itemType: Number(decoded.args.itemType ?? 0),
          z: Number(decoded.args.zIndex ?? 0),
          metadataUri: String(metadataUri),
        });
      }
      segment += 1;
      if (segment % 50 === 0) {
        console.log(
          `scanned_blocks=${start}-${end} parts_found=${partsById.size}`,
        );
      }
      start = end + 1;
    }
    parts = Array.from(partsById.values());
  }

  if (parts.length === 0) {
    throw errors[0] ?? new Error("catalog parts not found");
  }

  const report = {
    catalogAddress: CATALOG_ADDRESS,
    chain: CATALOG_CHAIN || null,
    rpcUrl: RPC_URL,
    totalParts: parts.length,
    missingMetadata: [] as Array<{
      part: CatalogPart;
      error: string;
      status?: number;
      timeout?: boolean;
      gateway?: string;
      attempts?: AttemptInfo[];
    }>,
    missingAssets: [] as Array<{
      part: CatalogPart;
      assetUri: string;
      error: string;
      status?: number;
      timeout?: boolean;
      gateway?: string;
      attempts?: AttemptInfo[];
    }>,
    noAssetUri: [] as CatalogPart[],
    okAssets: [] as Array<{
      part: CatalogPart;
      assetUri: string;
      gateway: string;
    }>,
  };

  const partResults = await mapWithConcurrency(parts, CONCURRENCY, async (part) => {
    if (!part.metadataUri) {
      return {
        kind: "missing_metadata" as const,
        part,
        error: "missing_metadata_uri",
      };
    }
    const meta = await fetchIpfsJson(part.metadataUri, gateways, timeoutMs);
    if (!meta.data) {
      return {
        kind: "missing_metadata" as const,
        part,
        error: meta.error ?? "fetch_failed",
        status: meta.status,
        timeout: meta.timeout,
        gateway: meta.gateway,
        attempts: meta.attempts,
      };
    }
    const assetUri = pickAssetUri(meta.data);
    if (!assetUri) {
      return {
        kind: "no_asset_uri" as const,
        part,
      };
    }
    const assetProbe = await probeIpfsAsset(assetUri, gateways, timeoutMs);
    if (assetProbe.ok) {
      return {
        kind: "ok_asset" as const,
        part,
        assetUri,
        gateway: assetProbe.gateway ?? "unknown",
      };
    }
    return {
      kind: "missing_asset" as const,
      part,
      assetUri,
      error: assetProbe.error ?? "fetch_failed",
      status: assetProbe.status,
      timeout: assetProbe.timeout,
      gateway: assetProbe.gateway,
      attempts: assetProbe.attempts,
    };
  });

  for (const result of partResults) {
    if (result.kind === "missing_metadata") {
      report.missingMetadata.push({
        part: result.part,
        error: result.error,
        status: result.status,
        timeout: result.timeout,
        gateway: result.gateway,
        attempts: result.attempts,
      });
      continue;
    }
    if (result.kind === "ok_asset") {
      report.okAssets.push({
        part: result.part,
        assetUri: result.assetUri,
        gateway: result.gateway,
      });
      continue;
    }
    if (result.kind === "no_asset_uri") {
      report.noAssetUri.push(result.part);
      continue;
    }
    report.missingAssets.push({
      part: result.part,
      assetUri: result.assetUri,
      error: result.error,
      status: result.status,
      timeout: result.timeout,
      gateway: result.gateway,
      attempts: result.attempts,
    });
  }

  const summary = {
    catalogAddress: report.catalogAddress,
    totalParts: report.totalParts,
    missingMetadata: report.missingMetadata.length,
    missingAssets: report.missingAssets.length,
    noAssetUri: report.noAssetUri.length,
    okAssets: report.okAssets.length,
    timeoutSeconds: TIMEOUT_SECONDS,
    gateways,
  };
  console.log(JSON.stringify(summary, null, 2));
  if (report.missingMetadata.length > 0) {
    console.log("Missing metadata:");
    for (const entry of report.missingMetadata) {
      console.log(
        `- part_index=${entry.part.index} metadata_uri=${entry.part.metadataUri} error=${entry.error}`,
      );
    }
  }
  if (report.missingAssets.length > 0) {
    console.log("Missing assets:");
    for (const entry of report.missingAssets) {
      console.log(
        `- part_index=${entry.part.index} metadata_uri=${entry.part.metadataUri} asset_uri=${entry.assetUri} error=${entry.error}`,
      );
    }
  }
  if (report.noAssetUri.length > 0) {
    console.log("Parts without asset URIs:");
    for (const part of report.noAssetUri) {
      console.log(`- part_index=${part.index} metadata_uri=${part.metadataUri}`);
    }
  }

  const outputPath = process.env.OUTPUT_PATH?.trim();
  if (outputPath) {
    await Bun.write(outputPath, JSON.stringify(report, null, 2));
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
