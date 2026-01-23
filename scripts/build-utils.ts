import { copyFile, mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { getAddress } from "ethers";

const REPO_ROOT = resolve(import.meta.dir, "..");
const TEMPLATES_DIR = join(REPO_ROOT, "src", "templates");
const DIST_ROOT = join(REPO_ROOT, "dist");

type EnvMap = Record<string, string>;

async function pathExists(path: string) {
  try {
    await stat(path);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw err;
  }
}

function stripQuotes(value: string) {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

async function readEnvFile(path: string): Promise<EnvMap> {
  const exists = await pathExists(path);
  if (!exists) {
    return {};
  }
  const raw = await readFile(path, "utf8");
  const env: EnvMap = {};
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const eq = trimmed.indexOf("=");
    if (eq === -1) {
      continue;
    }
    const key = trimmed.slice(0, eq).trim();
    const value = stripQuotes(trimmed.slice(eq + 1));
    env[key] = value;
  }
  return env;
}

async function loadEnv(): Promise<EnvMap> {
  const fileEnv = await readEnvFile(join(REPO_ROOT, ".env"));
  const merged: EnvMap = { ...fileEnv };
  for (const [key, value] of Object.entries(process.env)) {
    if (typeof value === "string") {
      merged[key] = value;
    }
  }
  return merged;
}

function parseJsonEnv<T>(env: EnvMap, key: string): T | undefined {
  const raw = env[key];
  if (!raw) return undefined;
  const normalized = stripQuotes(raw);
  try {
    return JSON.parse(normalized) as T;
  } catch (err) {
    throw new Error(`Invalid JSON in ${key}: ${(err as Error).message}`);
  }
}

function normalizeChainMap<T>(map: Record<string, T> | undefined): Record<string, T> {
  if (!map) return {};
  const normalized: Record<string, T> = {};
  for (const [key, value] of Object.entries(map)) {
    normalized[key.toLowerCase()] = value;
  }
  return normalized;
}

function parseNumber(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : undefined;
}

async function copyDir(srcDir: string, destDir: string) {
  await mkdir(destDir, { recursive: true });
  const entries = await readdir(srcDir);
  for (const name of entries) {
    const src = join(srcDir, name);
    const dest = join(destDir, name);
    const entry = await stat(src);
    if (entry.isDirectory()) {
      await copyDir(src, dest);
    } else if (entry.isFile()) {
      await copyFile(src, dest);
    }
  }
}

function buildApprovalConfig(env: EnvMap) {
  const approvalsContractsRaw = parseJsonEnv<Record<string, string>>(env, "APPROVALS_CONTRACTS");
  const approvalsContracts = normalizeChainMap(approvalsContractsRaw);
  const approvalChainRaw = env["APPROVALS_CONTRACT_CHAIN"];
  const approvalChain = approvalChainRaw?.trim().toLowerCase();

  const chainKeys = Object.keys(approvalsContracts);
  const resolvedChain =
    approvalChain ||
    (chainKeys.length === 1 ? chainKeys[0] : undefined);
  if (!resolvedChain) {
    throw new Error(
      "APPROVALS_CONTRACT_CHAIN is required when APPROVALS_CONTRACTS has multiple entries."
    );
  }

  const contractAddress = approvalsContracts[resolvedChain];
  if (!contractAddress) {
    throw new Error(`Missing approvals contract address for chain "${resolvedChain}".`);
  }

  const chainIdMapRaw = parseJsonEnv<Record<string, string>>(env, "CHAIN_ID_MAP");
  const chainIdMap: Record<string, string> = {};
  for (const [id, name] of Object.entries(chainIdMapRaw ?? {})) {
    chainIdMap[id] = name.toLowerCase();
  }

  const rpcEndpointsRaw = parseJsonEnv<Record<string, string[]>>(env, "RPC_ENDPOINTS");
  const rpcEndpoints = normalizeChainMap(rpcEndpointsRaw);
  const approvalRpcUrl =
    rpcEndpoints[resolvedChain]?.[0] ||
    (resolvedChain === "base" ? "https://mainnet.base.org" : undefined);
  if (!approvalRpcUrl) {
    throw new Error(`RPC endpoint missing for chain "${resolvedChain}".`);
  }

  let approvalContractChainId: number | undefined;
  for (const [chainId, name] of Object.entries(chainIdMap)) {
    if (name === resolvedChain) {
      approvalContractChainId = Number.parseInt(chainId, 10);
      break;
    }
  }

  const rendererBaseUrl = env["LANDING_RENDERER_BASE_URL"]?.trim() || undefined;
  const singularBaseUrl =
    env["LANDING_SINGULAR_BASE_URL"]?.trim() || "https://singular.rmrk.app";
  const maxCollections = parseNumber(env["LANDING_APPROVALS_LIMIT"]);
  const previewTokenCount = parseNumber(env["LANDING_APPROVALS_PREVIEW_TOKENS"]);

  return {
    approvalContractAddress: getAddress(contractAddress),
    approvalContractChain: resolvedChain,
    approvalContractChainId,
    approvalRpcUrl,
    chainIdMap,
    rendererBaseUrl,
    singularBaseUrl,
    maxCollections,
    previewTokenCount,
  };
}

function compactConfig<T extends Record<string, unknown>>(config: T) {
  return Object.fromEntries(
    Object.entries(config).filter(([, value]) => value !== undefined)
  );
}

export async function buildTemplate(templateName: string) {
  if (!templateName) {
    throw new Error("Template name is required.");
  }

  const templateDir = join(TEMPLATES_DIR, templateName);
  if (!(await pathExists(templateDir))) {
    throw new Error(`Template folder not found: ${templateDir}`);
  }

  const distDir = join(DIST_ROOT, templateName);
  await rm(distDir, { recursive: true, force: true });
  await mkdir(distDir, { recursive: true });

  const indexPath = join(templateDir, "index.html");
  if (!(await pathExists(indexPath))) {
    throw new Error(`Template is missing index.html: ${indexPath}`);
  }

  const cssPath = join(templateDir, "styles.css");
  if (await pathExists(cssPath)) {
    await copyFile(cssPath, join(distDir, "styles.css"));
  }

  const entryCandidates = ["app.ts", "app.js", "main.ts", "main.js"];
  let entryPath: string | undefined;
  for (const candidate of entryCandidates) {
    const target = join(templateDir, candidate);
    if (await pathExists(target)) {
      entryPath = target;
      break;
    }
  }

  if (entryPath) {
    const build = await Bun.build({
      entrypoints: [entryPath],
      target: "browser",
      format: "iife",
      minify: true,
      sourcemap: "none",
    });
    if (!build.success) {
      console.error(build.logs);
      throw new Error("Bundling failed.");
    }
    const output = build.outputs[0];
    if (!output) {
      throw new Error("Bundling produced no output.");
    }
    const bundledJs = await output.text();
    await writeFile(join(distDir, "app.js"), bundledJs, "utf8");
  }

  await copyFile(indexPath, join(distDir, "index.html"));

  for (const dirName of ["assets", "public"]) {
    const srcDir = join(templateDir, dirName);
    if (await pathExists(srcDir)) {
      await copyDir(srcDir, join(distDir, dirName));
    }
  }

  if (templateName === "approval") {
    const env = await loadEnv();
    const config = compactConfig(buildApprovalConfig(env));
    const configJs = `window.__APPROVAL_CONFIG__ = ${JSON.stringify(config, null, 2)};\n`;
    await writeFile(join(distDir, "config.js"), configJs, "utf8");
  }
}
