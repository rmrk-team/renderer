import {
  BrowserProvider,
  Contract,
  JsonRpcProvider,
  formatUnits,
  getAddress,
  isAddress,
} from "ethers";

type ApprovalConfig = {
  approvalContractAddress?: string;
  approvalContractChain?: string;
  approvalContractChainId?: number;
  approvalRpcUrl?: string;
  chainIdMap?: Record<string, string>;
  rendererBaseUrl?: string;
  singularBaseUrl?: string;
  maxCollections?: number;
  previewTokenCount?: number;
};

declare global {
  interface Window {
    __APPROVAL_CONFIG__?: ApprovalConfig;
    ethereum?: {
      request?: (args: { method: string; params?: unknown[] }) => Promise<unknown>;
    };
  }
}

const APPROVALS_ABI = [
  "function approvalKeyCount() view returns (uint256)",
  "function approvalKeysPage(uint256 start, uint256 limit) view returns (uint256[] chainIds, address[] collections, uint64[] approvedUntil)",
  "function approvedUntil(uint256 chainId, address collection) view returns (uint64)",
  "function fee() view returns (uint256)",
  "function token() view returns (address)",
  "function paused() view returns (bool)",
  "function approve(uint256 chainId, address collection)",
];

const ERC20_ABI = [
  "function symbol() view returns (string)",
  "function decimals() view returns (uint8)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)",
];

const config = window.__APPROVAL_CONFIG__ ?? ({} as ApprovalConfig);
const chainIdMap = config.chainIdMap ?? {};

const approvalStatus = document.getElementById("approval-status");
const approvedCount = document.getElementById("approved-count");
const approvedTotal = document.getElementById("approved-total");
const approvedGrid = document.getElementById("approved-collections");
const approvedLoading = document.getElementById("approved-loading");
const approvedEmpty = document.getElementById("approved-empty");
const walletStatus = document.getElementById("wallet-status");
const connectWalletButton = document.getElementById("connect-wallet");
const approveForm = document.getElementById("approve-form") as HTMLFormElement | null;
const approveCollectionInput = document.getElementById(
  "approve-collection"
) as HTMLInputElement | null;
const approveChainSelect = document.getElementById(
  "approve-chain"
) as HTMLSelectElement | null;
const approveChainIdInput = document.getElementById(
  "approve-chain-id"
) as HTMLInputElement | null;
const approveStatus = document.getElementById("approve-status");

let approvalsContract: Contract | null = null;
let approvalTokenAddress = "";
let approvalTokenSymbol = "TOKEN";
let approvalTokenDecimals = 18;
let approvalFee = 0n;
let approvalPaused = false;

function setText(id: string, value: string) {
  const element = document.getElementById(id);
  if (element) {
    element.textContent = value;
  }
}

function setStatus(target: HTMLElement | null, message: string) {
  if (target) {
    target.textContent = message;
  }
}

function normalizeBaseUrl(url: string) {
  return url.replace(/\/+$/, "");
}

function shortAddress(address: string) {
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

function formatApprovedUntil(value: bigint) {
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (value === 0n) return "revoked";
  if (value > now + 315360000n) {
    return "permanent";
  }
  if (value <= now) return "expired";
  return new Date(Number(value) * 1000).toLocaleString();
}

function buildTokenIds(count: number) {
  return Array.from({ length: count }, (_, i) => i + 1);
}

function buildChainSelectOptions() {
  if (!approveChainSelect || !approveChainIdInput) {
    return;
  }
  const entries = Object.entries(chainIdMap)
    .map(([chainId, name]) => ({ chainId, name }))
    .sort((a, b) => a.name.localeCompare(b.name));
  approveChainSelect.innerHTML = "";
  if (entries.length === 0) {
    approveChainSelect.classList.add("hidden");
    approveChainIdInput.readOnly = false;
    return;
  }
  for (const entry of entries) {
    const option = document.createElement("option");
    option.value = entry.chainId;
    option.textContent = `${entry.name} (${entry.chainId})`;
    approveChainSelect.appendChild(option);
  }
  const customOption = document.createElement("option");
  customOption.value = "custom";
  customOption.textContent = "custom chain id...";
  approveChainSelect.appendChild(customOption);

  approveChainSelect.value = entries[0].chainId;
  approveChainIdInput.value = entries[0].chainId;
  approveChainIdInput.readOnly = true;

  approveChainSelect.addEventListener("change", () => {
    if (approveChainSelect.value === "custom") {
      approveChainIdInput.readOnly = false;
      approveChainIdInput.value = "";
    } else {
      approveChainIdInput.readOnly = true;
      approveChainIdInput.value = approveChainSelect.value;
    }
  });
}

async function loadContractDetails() {
  if (!approvalsContract) return;
  const [fee, token, paused] = await Promise.all([
    approvalsContract.fee(),
    approvalsContract.token(),
    approvalsContract.paused(),
  ]);
  approvalFee = BigInt(fee);
  approvalTokenAddress = getAddress(token);
  approvalPaused = Boolean(paused);

  const tokenContract = new Contract(
    approvalTokenAddress,
    ERC20_ABI,
    approvalsContract.runner
  );
  try {
    approvalTokenSymbol = await tokenContract.symbol();
  } catch {
    approvalTokenSymbol = "TOKEN";
  }
  try {
    approvalTokenDecimals = Number(await tokenContract.decimals());
  } catch {
    approvalTokenDecimals = 18;
  }

  setText("approval-fee", formatUnits(approvalFee, approvalTokenDecimals));
  setText("approval-token", approvalTokenSymbol);
  setText("approve-fee", formatUnits(approvalFee, approvalTokenDecimals));
  setText("approve-token", approvalTokenSymbol);

  if (approvalPaused) {
    setStatus(
      approveStatus,
      "Approvals are paused on-chain. New approvals are temporarily disabled."
    );
  }
}

async function loadApprovedCollections() {
  if (!approvalsContract) return;
  if (approvedLoading) approvedLoading.classList.remove("hidden");
  if (approvedEmpty) approvedEmpty.classList.add("hidden");

  const total = Number(await approvalsContract.approvalKeyCount());
  const maxCollections = config.maxCollections ?? 8;
  const previewTokenCount = config.previewTokenCount ?? 4;
  const approved: Array<{
    chainId: number;
    chainName?: string;
    collection: string;
    approvedUntil: bigint;
  }> = [];

  let start = 0;
  const pageSize = 200;
  const now = BigInt(Math.floor(Date.now() / 1000));

  while (start < total && approved.length < maxCollections) {
    const page = await approvalsContract.approvalKeysPage(start, pageSize);
    const chainIds = page[0] as bigint[];
    const collections = page[1] as string[];
    const approvedUntil = page[2] as bigint[];

    for (let i = 0; i < collections.length; i += 1) {
      const approvedValue = BigInt(approvedUntil[i] ?? 0);
      if (approvedValue <= now) continue;
      const chainId = Number(chainIds[i]);
      const chainName = chainIdMap[String(chainId)];
      approved.push({
        chainId,
        chainName,
        collection: getAddress(collections[i]),
        approvedUntil: approvedValue,
      });
      if (approved.length >= maxCollections) break;
    }
    start += pageSize;
  }

  if (approvedCount) approvedCount.textContent = String(approved.length);
  if (approvedTotal) approvedTotal.textContent = String(total);

  if (approvedLoading) approvedLoading.classList.add("hidden");

  if (approved.length === 0 && approvedEmpty) {
    approvedEmpty.classList.remove("hidden");
  }

  if (!approvedGrid) return;
  approvedGrid.innerHTML = "";

  const rendererBase = normalizeBaseUrl(
    config.rendererBaseUrl || window.location.origin
  );
  const singularBase = normalizeBaseUrl(
    config.singularBaseUrl || "https://singular.rmrk.app"
  );

  for (const entry of approved) {
    const card = document.createElement("div");
    card.className = "collection-card";

    const header = document.createElement("div");
    header.className = "collection-header";

    const title = document.createElement("div");
    const name = document.createElement("div");
    name.textContent = shortAddress(entry.collection);
    name.className = "mono";
    const chainPill = document.createElement("span");
    chainPill.className = "chain-pill";
    chainPill.textContent = entry.chainName
      ? entry.chainName
      : `chain ${entry.chainId}`;
    title.appendChild(name);
    title.appendChild(chainPill);

    const link = document.createElement("a");
    const chainSlug = entry.chainName;
    if (chainSlug) {
      link.href = `${singularBase}/collectibles/${chainSlug}/${entry.collection}`;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = "View on Singular";
      link.className = "button ghost";
    } else {
      link.textContent = "Chain not mapped";
      link.className = "button ghost";
    }

    header.appendChild(title);
    header.appendChild(link);

    const meta = document.createElement("div");
    meta.className = "collection-meta";
    meta.innerHTML = `
      <div>Approved until: ${formatApprovedUntil(entry.approvedUntil)}</div>
      <div>Collection: <span class="mono">${entry.collection}</span></div>
    `;

    card.appendChild(header);
    card.appendChild(meta);

    if (chainSlug) {
      const grid = document.createElement("div");
      grid.className = "nft-grid";
      for (const tokenId of buildTokenIds(previewTokenCount)) {
        const anchor = document.createElement("a");
        anchor.href = `${singularBase}/collectibles/${chainSlug}/${entry.collection}`;
        anchor.target = "_blank";
        anchor.rel = "noopener noreferrer";

        const img = document.createElement("img");
        img.loading = "lazy";
        img.alt = `${chainSlug} #${tokenId}`;
        img.src = `${rendererBase}/render/${chainSlug}/${entry.collection}/${tokenId}/png?cache=0&width=320&onerror=placeholder`;
        anchor.appendChild(img);
        grid.appendChild(anchor);
      }
      card.appendChild(grid);
    }

    approvedGrid.appendChild(card);
  }
}

async function connectWallet() {
  if (!window.ethereum) {
    setStatus(
      approveStatus,
      "No injected wallet found. Install a wallet like MetaMask to continue."
    );
    throw new Error("Wallet not available");
  }
  const provider = new BrowserProvider(window.ethereum);
  await provider.send("eth_requestAccounts", []);
  const signer = await provider.getSigner();
  const address = await signer.getAddress();
  if (walletStatus) {
    walletStatus.textContent = shortAddress(address);
  }
  return provider;
}

async function ensureCorrectNetwork(provider: BrowserProvider) {
  if (!config.approvalContractChainId || !window.ethereum?.request) {
    return;
  }
  const network = await provider.getNetwork();
  const chainId = Number(network.chainId);
  if (chainId === config.approvalContractChainId) {
    return;
  }
  const hexChainId = `0x${config.approvalContractChainId.toString(16)}`;
  await window.ethereum.request({
    method: "wallet_switchEthereumChain",
    params: [{ chainId: hexChainId }],
  });
}

async function handleApprove(event: Event) {
  event.preventDefault();
  if (!approvalsContract || !approveCollectionInput || !approveChainIdInput) {
    return;
  }

  const collectionAddress = approveCollectionInput.value.trim();
  if (!isAddress(collectionAddress)) {
    setStatus(approveStatus, "Enter a valid collection address.");
    return;
  }

  const chainIdValue = Number.parseInt(approveChainIdInput.value, 10);
  if (!Number.isFinite(chainIdValue) || chainIdValue <= 0) {
    setStatus(approveStatus, "Enter a valid chain id.");
    return;
  }

  try {
    setStatus(approveStatus, "Connecting wallet...");
    const provider = await connectWallet();
    await ensureCorrectNetwork(provider);
    const signer = await provider.getSigner();
    const signerAddress = await signer.getAddress();

    if (approvalPaused) {
      setStatus(
        approveStatus,
        "Approvals are currently paused on-chain. Try again later."
      );
      return;
    }

    const approvalWithSigner = new Contract(
      approvalsContract.target,
      APPROVALS_ABI,
      signer
    );

    if (approvalFee > 0n) {
      const tokenContract = new Contract(
        approvalTokenAddress,
        ERC20_ABI,
        signer
      );
      const allowance = BigInt(
        await tokenContract.allowance(signerAddress, approvalsContract.target)
      );
      if (allowance < approvalFee) {
        setStatus(
          approveStatus,
          `Approving ${approvalTokenSymbol} allowance...`
        );
        const approveTx = await tokenContract.approve(
          approvalsContract.target,
          approvalFee
        );
        await approveTx.wait();
      }
    }

    setStatus(approveStatus, "Submitting approval...");
    const tx = await approvalWithSigner.approve(chainIdValue, collectionAddress);
    await tx.wait();
    setStatus(approveStatus, "Collection approved. Updating list...");
    await loadApprovedCollections();
    setStatus(approveStatus, "Approval complete.");
  } catch (err) {
    const message = err instanceof Error ? err.message : "Approval failed.";
    setStatus(approveStatus, message);
  }
}

async function init() {
  try {
    if (!config.approvalContractAddress || !config.approvalRpcUrl) {
      throw new Error(
        "Missing approvals config. Build with APPROVALS_CONTRACTS + RPC_ENDPOINTS in .env."
      );
    }
    const contractAddress = getAddress(config.approvalContractAddress);
    const chainName = config.approvalContractChain || "unknown";
    setText("approval-contract-address", shortAddress(contractAddress));
    const addrEl = document.getElementById("approval-contract-address");
    if (addrEl) addrEl.setAttribute("title", contractAddress);
    setText("approval-contract-chain", chainName);

    approvalsContract = new Contract(
      contractAddress,
      APPROVALS_ABI,
      new JsonRpcProvider(config.approvalRpcUrl)
    );
    await loadContractDetails();
    await loadApprovedCollections();
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to load.";
    setStatus(approvalStatus, message);
    if (approvedLoading) approvedLoading.classList.add("hidden");
  }
}

if (connectWalletButton) {
  connectWalletButton.addEventListener("click", async () => {
    try {
      await connectWallet();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Wallet error.";
      setStatus(approveStatus, message);
    }
  });
}

if (approveForm) {
  approveForm.addEventListener("submit", handleApprove);
}

buildChainSelectOptions();
init();
