const authInput = document.getElementById('authToken');
const authStatus = document.getElementById('authStatus');

function saveToken() {
  const token = authInput.value.trim();
  if (!token) return;
  authStatus.textContent = 'Token set for this session';
}

function authHeaders() {
  const token = authInput.value.trim();
  return token ? { 'Authorization': 'Bearer ' + token } : {};
}

async function apiFetch(path, options = {}) {
  const headers = Object.assign({}, options.headers || {}, authHeaders());
  if (options.body && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }
  const response = await fetch(path, Object.assign({}, options, { headers }));
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.statusText);
  }
  if (response.headers.get('content-type')?.includes('application/json')) {
    return response.json();
  }
  return response.text();
}

async function loadCollections() {
  const data = await apiFetch('/admin/api/collections');
  const table = document.getElementById('collectionsTable');
  table.innerHTML = '';
  data.forEach(item => {
    const row = document.createElement('tr');
    const chainCell = document.createElement('td');
    chainCell.textContent = item.chain;
    const collectionCell = document.createElement('td');
    collectionCell.textContent = item.collection_address;
    const canvasCell = document.createElement('td');
    const width = item.canvas_width ?? '-';
    const height = item.canvas_height ?? '-';
    canvasCell.textContent = `${width}x${height}`;
    const epochCell = document.createElement('td');
    epochCell.textContent = item.cache_epoch ?? '-';
    const approvedCell = document.createElement('td');
    approvedCell.textContent = item.approved;
    const actionsCell = document.createElement('td');

    const approveBtn = document.createElement('button');
    approveBtn.textContent = 'Approve';
    approveBtn.addEventListener('click', () => approveCollection(item.chain, item.collection_address, true));
    const unapproveBtn = document.createElement('button');
    unapproveBtn.textContent = 'Unapprove';
    unapproveBtn.addEventListener('click', () => approveCollection(item.chain, item.collection_address, false));
    const deleteBtn = document.createElement('button');
    deleteBtn.textContent = 'Delete';
    deleteBtn.addEventListener('click', () => deleteCollection(item.chain, item.collection_address));

    actionsCell.appendChild(approveBtn);
    actionsCell.appendChild(unapproveBtn);
    actionsCell.appendChild(deleteBtn);

    row.appendChild(chainCell);
    row.appendChild(collectionCell);
    row.appendChild(canvasCell);
    row.appendChild(epochCell);
    row.appendChild(approvedCell);
    row.appendChild(actionsCell);
    table.appendChild(row);
  });
}

async function saveCollection() {
  const payload = {
    chain: document.getElementById('colChain').value.trim(),
    collection_address: document.getElementById('colAddress').value.trim(),
    og_focal_point: parseInt(document.getElementById('colOgFocal').value || '25', 10),
    og_overlay_uri: document.getElementById('colOgOverlay').value.trim() || null,
    watermark_overlay_uri: document.getElementById('colWatermark').value.trim() || null,
    warmup_strategy: document.getElementById('colWarmupStrategy').value.trim() || null,
    approved: document.getElementById('colApproved').value === 'true'
  };
  await apiFetch('/admin/api/collections', { method: 'POST', body: JSON.stringify(payload) });
  await loadCollections();
}

async function approveCollection(chain, collection, approved) {
  await apiFetch(`/admin/api/collections/${chain}/${collection}/approve`, {
    method: 'POST',
    body: JSON.stringify({ approved })
  });
  await loadCollections();
}

async function deleteCollection(chain, collection) {
  await apiFetch(`/admin/api/collections/${chain}/${collection}`, { method: 'DELETE' });
  await loadCollections();
}

async function updateCacheEpoch() {
  const chain = document.getElementById('epochChain').value.trim();
  const collection = document.getElementById('epochCollection').value.trim();
  const epochRaw = document.getElementById('epochValue').value.trim();
  const payload = epochRaw ? { epoch: parseInt(epochRaw, 10) } : {};
  const result = await apiFetch(`/admin/api/collections/${chain}/${collection}/cache-epoch`, {
    method: 'POST',
    body: JSON.stringify(payload)
  });
  document.getElementById('epochStatus').textContent = `Epoch set to ${result.epoch}`;
}

async function refreshCanvas() {
  const chain = document.getElementById('refreshChain').value.trim();
  const collection = document.getElementById('refreshCollection').value.trim();
  const payload = {
    token_id: document.getElementById('refreshToken').value.trim(),
    asset_id: document.getElementById('refreshAsset').value.trim(),
  };
  const result = await apiFetch(`/admin/api/collections/${chain}/${collection}/refresh-canvas`, {
    method: 'POST',
    body: JSON.stringify(payload)
  });
  document.getElementById('refreshStatus').textContent = `Canvas: ${result.canvas_width}x${result.canvas_height}`;
}

async function startWarmup() {
  const tokensRaw = document.getElementById('warmTokens').value.trim();
  const payload = {
    chain: document.getElementById('warmChain').value.trim(),
    collection: document.getElementById('warmCollection').value.trim(),
    token_ids: tokensRaw ? tokensRaw.split(',').map(x => x.trim()).filter(Boolean) : null,
    asset_id: document.getElementById('warmAsset').value.trim() || null,
    cache_timestamp: document.getElementById('warmCache').value.trim() || null,
    widths: document.getElementById('warmWidths').value.trim()
      ? document.getElementById('warmWidths').value.split(',').map(x => x.trim()).filter(Boolean)
      : null,
    include_og: document.getElementById('warmOg').value === 'true',
    strategy: document.getElementById('warmStrategy').value,
    from_block: document.getElementById('warmFromBlock').value ? parseInt(document.getElementById('warmFromBlock').value, 10) : null,
    to_block: document.getElementById('warmToBlock').value ? parseInt(document.getElementById('warmToBlock').value, 10) : null,
    range_start: document.getElementById('warmRangeStart').value ? parseInt(document.getElementById('warmRangeStart').value, 10) : null,
    range_end: document.getElementById('warmRangeEnd').value ? parseInt(document.getElementById('warmRangeEnd').value, 10) : null,
    allow_sequential: document.getElementById('warmSequential').value === 'true',
  };
  const result = await apiFetch('/admin/api/warmup', { method: 'POST', body: JSON.stringify(payload) });
  document.getElementById('warmupStatus').textContent = `Queued ${result.jobs} jobs`;
}

async function startCatalogWarmup() {
  const payload = {
    chain: document.getElementById('catalogWarmChain').value.trim(),
    collection: document.getElementById('catalogWarmCollection').value.trim(),
    catalog_address: document.getElementById('catalogWarmAddress').value.trim() || null,
    token_id: document.getElementById('catalogWarmToken').value.trim() || null,
    asset_id: document.getElementById('catalogWarmAsset').value.trim() || null,
    from_block: document.getElementById('catalogWarmFromBlock').value
      ? parseInt(document.getElementById('catalogWarmFromBlock').value, 10)
      : null,
    to_block: document.getElementById('catalogWarmToBlock').value
      ? parseInt(document.getElementById('catalogWarmToBlock').value, 10)
      : null,
    force: document.getElementById('catalogWarmForce').value === 'true',
  };
  const result = await apiFetch('/admin/api/warmup/catalog', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
  document.getElementById('catalogWarmupStatus').textContent =
    `Job ${result.job_id}: ${result.parts_total} parts queued`;
}

async function startTokenWarmupRange() {
  const payload = {
    chain: document.getElementById('tokenWarmChain').value.trim(),
    collection: document.getElementById('tokenWarmCollection').value.trim(),
    start_token: parseInt(document.getElementById('tokenWarmStart').value, 10),
    end_token: parseInt(document.getElementById('tokenWarmEnd').value, 10),
    step: document.getElementById('tokenWarmStep').value
      ? parseInt(document.getElementById('tokenWarmStep').value, 10)
      : null,
    asset_id: document.getElementById('tokenWarmAsset').value.trim() || null,
    force: document.getElementById('tokenWarmForce').value === 'true',
  };
  const result = await apiFetch('/admin/api/warmup/tokens', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
  document.getElementById('tokenWarmupStatus').textContent =
    `Job ${result.job_id}: ${result.tokens_total} tokens queued`;
}

async function startTokenWarmupManual() {
  const tokensRaw = document.getElementById('tokenWarmTokens').value.trim();
  const payload = {
    chain: document.getElementById('tokenWarmChain').value.trim(),
    collection: document.getElementById('tokenWarmCollection').value.trim(),
    token_ids: tokensRaw ? tokensRaw.split(',').map(x => x.trim()).filter(Boolean) : [],
    asset_id: document.getElementById('tokenWarmAsset').value.trim() || null,
    force: document.getElementById('tokenWarmForce').value === 'true',
  };
  const result = await apiFetch('/admin/api/warmup/tokens/manual', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
  document.getElementById('tokenWarmupStatus').textContent =
    `Job ${result.job_id}: ${result.tokens_total} tokens queued`;
}

async function loadWarmupStats() {
  const result = await apiFetch('/admin/api/warmup');
  document.getElementById('warmupStatus').textContent =
    `queued=${result.queued}, running=${result.running}, done=${result.done}, failed=${result.failed}, paused=${result.paused}`;
}

async function loadCatalogWarmupStatus() {
  const chain = document.getElementById('catalogWarmChain').value.trim();
  const collection = document.getElementById('catalogWarmCollection').value.trim();
  if (!chain || !collection) return;
  const result = await apiFetch(`/admin/api/warmup/status?chain=${encodeURIComponent(chain)}&collection=${encodeURIComponent(collection)}`);
  document.getElementById('catalogWarmupStatus').textContent =
    `status=${result.status}, parts=${result.parts_done}/${result.parts_total}, assets=${result.assets_pinned}/${result.assets_total}, failed=${result.assets_failed}`;
}

async function loadTokenWarmupStatus() {
  const chain = document.getElementById('tokenWarmChain').value.trim();
  const collection = document.getElementById('tokenWarmCollection').value.trim();
  if (!chain || !collection) return;
  const result = await apiFetch(`/admin/api/warmup/status?chain=${encodeURIComponent(chain)}&collection=${encodeURIComponent(collection)}`);
  document.getElementById('tokenWarmupStatus').textContent =
    `status=${result.token_status}, tokens=${result.tokens_done}/${result.tokens_total}, assets=${result.token_assets_pinned}/${result.token_assets_total}, failed=${result.token_assets_failed}`;
}

async function loadWarmupJobs() {
  const data = await apiFetch('/admin/api/warmup/jobs?limit=100');
  const table = document.getElementById('warmupJobsTable');
  table.innerHTML = '';
  data.forEach(item => {
    const row = document.createElement('tr');
    const idCell = document.createElement('td');
    idCell.textContent = item.id;
    const chainCell = document.createElement('td');
    chainCell.textContent = item.chain;
    const collectionCell = document.createElement('td');
    collectionCell.textContent = item.collection_address;
    const tokenCell = document.createElement('td');
    tokenCell.textContent = item.token_id;
    const statusCell = document.createElement('td');
    statusCell.textContent = item.status;
    const errorCell = document.createElement('td');
    errorCell.textContent = item.last_error ?? '-';
    const actionsCell = document.createElement('td');
    const cancelBtn = document.createElement('button');
    cancelBtn.textContent = 'Cancel';
    cancelBtn.disabled = item.status !== 'queued' && item.status !== 'running';
    cancelBtn.addEventListener('click', () => cancelWarmupJob(item.id));
    actionsCell.appendChild(cancelBtn);
    row.appendChild(idCell);
    row.appendChild(chainCell);
    row.appendChild(collectionCell);
    row.appendChild(tokenCell);
    row.appendChild(statusCell);
    row.appendChild(errorCell);
    row.appendChild(actionsCell);
    table.appendChild(row);
  });
}

async function cancelWarmupJob(id) {
  await apiFetch(`/admin/api/warmup/jobs/${id}/cancel`, { method: 'POST' });
  await loadWarmupJobs();
}

async function pauseWarmup() {
  await apiFetch('/admin/api/warmup/pause', { method: 'POST' });
  await loadWarmupStats();
}

async function resumeWarmup() {
  await apiFetch('/admin/api/warmup/resume', { method: 'POST' });
  await loadWarmupStats();
}

async function loadCacheStats() {
  const stats = await apiFetch('/admin/api/cache');
  document.getElementById('cacheStats').textContent =
    `renders=${stats.render_bytes} bytes, assets=${stats.asset_bytes} bytes`;
}

async function purgeCollection() {
  const payload = {
    chain: document.getElementById('purgeChain').value.trim(),
    collection: document.getElementById('purgeCollection').value.trim()
  };
  await apiFetch('/admin/api/cache/purge', { method: 'POST', body: JSON.stringify(payload) });
  await loadCacheStats();
}

async function purgeRenders() {
  await apiFetch('/admin/api/cache/purge', { method: 'POST', body: JSON.stringify({}) });
  await loadCacheStats();
}

async function purgeAll() {
  await apiFetch('/admin/api/cache/purge', { method: 'POST', body: JSON.stringify({ include_assets: true }) });
  await loadCacheStats();
}

async function loadHashReplacements() {
  const data = await apiFetch('/admin/api/hash-replacements');
  const table = document.getElementById('hashReplacementTable');
  table.innerHTML = '';
  data.forEach(item => {
    const row = document.createElement('tr');
    const cidCell = document.createElement('td');
    cidCell.textContent = item.cid;
    const typeCell = document.createElement('td');
    typeCell.textContent = item.content_type;
    const pathCell = document.createElement('td');
    pathCell.textContent = item.file_path;
    const actionsCell = document.createElement('td');
    const deleteBtn = document.createElement('button');
    deleteBtn.textContent = 'Delete';
    deleteBtn.addEventListener('click', () => deleteHashReplacement(item.cid));
    actionsCell.appendChild(deleteBtn);
    row.appendChild(cidCell);
    row.appendChild(typeCell);
    row.appendChild(pathCell);
    row.appendChild(actionsCell);
    table.appendChild(row);
  });
}

async function uploadHashReplacement() {
  const cid = document.getElementById('hashReplacementCid').value.trim();
  const fileInput = document.getElementById('hashReplacementFile');
  const status = document.getElementById('hashReplacementStatus');
  const file = fileInput.files && fileInput.files[0];
  if (!cid || !file) {
    status.textContent = 'CID and file are required';
    return;
  }
  const form = new FormData();
  form.append('cid', cid);
  form.append('file', file);
  const response = await fetch('/admin/api/hash-replacements', {
    method: 'POST',
    headers: authHeaders(),
    body: form,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.statusText);
  }
  status.textContent = `Uploaded ${cid}`;
  await loadHashReplacements();
}

async function deleteHashReplacement(cid) {
  await apiFetch(`/admin/api/hash-replacements/${encodeURIComponent(cid)}`, { method: 'DELETE' });
  await loadHashReplacements();
}

async function loadRpc() {
  const chain = document.getElementById('rpcChain').value.trim();
  const data = await apiFetch(`/admin/api/rpc/${chain}`);
  document.getElementById('rpcJson').value = JSON.stringify(data, null, 2);
}

async function saveRpc() {
  const chain = document.getElementById('rpcChain').value.trim();
  const payload = JSON.parse(document.getElementById('rpcJson').value || '[]');
  await apiFetch(`/admin/api/rpc/${chain}`, { method: 'PUT', body: JSON.stringify(payload) });
  document.getElementById('rpcStatus').textContent = 'RPC endpoints saved';
}

async function loadRpcHealth() {
  const chain = document.getElementById('rpcChain').value.trim();
  const data = await apiFetch(`/admin/api/rpc/${chain}/health`);
  const table = document.getElementById('rpcHealthTable');
  table.innerHTML = '';
  data.forEach(item => {
    const row = document.createElement('tr');
    const urlCell = document.createElement('td');
    urlCell.textContent = item.url;
    const okCell = document.createElement('td');
    okCell.textContent = item.ok;
    const blockCell = document.createElement('td');
    blockCell.textContent = item.block_number ?? '-';
    const latencyCell = document.createElement('td');
    latencyCell.textContent = item.latency_ms ?? '-';
    const errorCell = document.createElement('td');
    errorCell.textContent = item.error ?? '-';

    row.appendChild(urlCell);
    row.appendChild(okCell);
    row.appendChild(blockCell);
    row.appendChild(latencyCell);
    row.appendChild(errorCell);
    table.appendChild(row);
  });
}

async function loadSettings() {
  const data = await apiFetch('/admin/api/settings');
  const select = document.getElementById('requireApproval');
  if (data.require_approval_override === null) {
    select.value = 'inherit';
  } else {
    select.value = data.require_approval_override ? 'true' : 'false';
  }
  document.getElementById('settingsStatus').textContent = `Effective: ${data.require_approval}`;
}

async function updateRequireApproval() {
  const value = document.getElementById('requireApproval').value;
  const payload = value === 'inherit' ? { require_approval: null } : { require_approval: value === 'true' };
  await apiFetch('/admin/api/settings/require-approval', { method: 'PUT', body: JSON.stringify(payload) });
  await loadSettings();
}

async function loadClients() {
  const data = await apiFetch('/admin/api/clients');
  const table = document.getElementById('clientsTable');
  table.innerHTML = '';
  data.forEach(item => {
    const row = document.createElement('tr');
    const idCell = document.createElement('td');
    idCell.textContent = item.id;
    const nameCell = document.createElement('td');
    nameCell.textContent = item.name;
    const notesCell = document.createElement('td');
    notesCell.textContent = item.notes ?? '';
    const actionsCell = document.createElement('td');
    const deleteBtn = document.createElement('button');
    deleteBtn.textContent = 'Delete';
    deleteBtn.addEventListener('click', () => deleteClient(item.id));
    actionsCell.appendChild(deleteBtn);
    row.appendChild(idCell);
    row.appendChild(nameCell);
    row.appendChild(notesCell);
    row.appendChild(actionsCell);
    table.appendChild(row);
  });
}

async function createClient() {
  const payload = {
    name: document.getElementById('clientName').value.trim(),
    notes: document.getElementById('clientNotes').value.trim() || null
  };
  const result = await apiFetch('/admin/api/clients', { method: 'POST', body: JSON.stringify(payload) });
  document.getElementById('clientStatus').textContent = `Created client ${result.id}`;
  await loadClients();
}

async function deleteClient(id) {
  await apiFetch(`/admin/api/clients/${id}`, { method: 'DELETE' });
  await loadClients();
}

async function loadClientKeys() {
  const clientId = document.getElementById('clientKeyClientId').value.trim();
  if (!clientId) return;
  const data = await apiFetch(`/admin/api/clients/${clientId}/keys`);
  const table = document.getElementById('clientKeysTable');
  table.innerHTML = '';
  data.forEach(item => {
    const row = document.createElement('tr');
    const idCell = document.createElement('td');
    idCell.textContent = item.id;
    const prefixCell = document.createElement('td');
    prefixCell.textContent = item.key_prefix;
    const activeCell = document.createElement('td');
    activeCell.textContent = item.active;
    const rateCell = document.createElement('td');
    rateCell.textContent = item.rate_limit_per_minute ?? '-';
    const burstCell = document.createElement('td');
    burstCell.textContent = item.burst ?? '-';
    const freshCell = document.createElement('td');
    freshCell.textContent = item.allow_fresh ? 'true' : 'false';
    const actionsCell = document.createElement('td');
    const revokeBtn = document.createElement('button');
    revokeBtn.textContent = 'Revoke';
    revokeBtn.addEventListener('click', () => revokeClientKey(item.id));
    actionsCell.appendChild(revokeBtn);
    row.appendChild(idCell);
    row.appendChild(prefixCell);
    row.appendChild(activeCell);
    row.appendChild(rateCell);
    row.appendChild(burstCell);
    row.appendChild(freshCell);
    row.appendChild(actionsCell);
    table.appendChild(row);
  });
}

async function createClientKey() {
  const clientId = document.getElementById('clientKeyClientId').value.trim();
  if (!clientId) return;
  const payload = {
    rate_limit_per_minute: document.getElementById('clientKeyRate').value ? parseInt(document.getElementById('clientKeyRate').value, 10) : null,
    burst: document.getElementById('clientKeyBurst').value ? parseInt(document.getElementById('clientKeyBurst').value, 10) : null,
    max_concurrent_renders_override: document.getElementById('clientKeyConcurrent').value ? parseInt(document.getElementById('clientKeyConcurrent').value, 10) : null,
    allow_fresh: document.getElementById('clientKeyAllowFresh').value === 'true'
  };
  const result = await apiFetch(`/admin/api/clients/${clientId}/keys`, { method: 'POST', body: JSON.stringify(payload) });
  document.getElementById('clientKeyStatus').textContent = `Key created: ${result.api_key} (copy now)`;
  await loadClientKeys();
}

async function revokeClientKey(keyId) {
  await apiFetch(`/admin/api/clients/keys/${keyId}`, { method: 'DELETE' });
  await loadClientKeys();
}

async function loadIpRules() {
  const data = await apiFetch('/admin/api/ip-rules');
  const table = document.getElementById('ipRulesTable');
  table.innerHTML = '';
  data.forEach(item => {
    const row = document.createElement('tr');
    const idCell = document.createElement('td');
    idCell.textContent = item.id;
    const cidrCell = document.createElement('td');
    cidrCell.textContent = item.ip_cidr;
    const modeCell = document.createElement('td');
    modeCell.textContent = item.mode;
    const actionsCell = document.createElement('td');
    const deleteBtn = document.createElement('button');
    deleteBtn.textContent = 'Delete';
    deleteBtn.addEventListener('click', () => deleteIpRule(item.id));
    actionsCell.appendChild(deleteBtn);
    row.appendChild(idCell);
    row.appendChild(cidrCell);
    row.appendChild(modeCell);
    row.appendChild(actionsCell);
    table.appendChild(row);
  });
}

async function createIpRule() {
  const payload = {
    ip_cidr: document.getElementById('ipRuleCidr').value.trim(),
    mode: document.getElementById('ipRuleMode').value
  };
  await apiFetch('/admin/api/ip-rules', { method: 'POST', body: JSON.stringify(payload) });
  await loadIpRules();
}

async function deleteIpRule(id) {
  await apiFetch(`/admin/api/ip-rules/${id}`, { method: 'DELETE' });
  await loadIpRules();
}

async function loadUsage() {
  const hours = document.getElementById('usageHours').value.trim() || '24';
  const data = await apiFetch(`/admin/api/usage?hours=${hours}`);
  const table = document.getElementById('usageTable');
  table.innerHTML = '';
  data.forEach(item => {
    const row = document.createElement('tr');
    const hourCell = document.createElement('td');
    hourCell.textContent = item.hour_bucket;
    const identityCell = document.createElement('td');
    identityCell.textContent = item.identity_key;
    const routeCell = document.createElement('td');
    routeCell.textContent = item.route_group;
    const requestsCell = document.createElement('td');
    requestsCell.textContent = item.requests;
    const bytesCell = document.createElement('td');
    bytesCell.textContent = item.bytes_out;
    const hitCell = document.createElement('td');
    hitCell.textContent = item.cache_hits;
    const missCell = document.createElement('td');
    missCell.textContent = item.cache_misses;
    row.appendChild(hourCell);
    row.appendChild(identityCell);
    row.appendChild(routeCell);
    row.appendChild(requestsCell);
    row.appendChild(bytesCell);
    row.appendChild(hitCell);
    row.appendChild(missCell);
    table.appendChild(row);
  });
}

function bindClick(id, handler) {
  const button = document.getElementById(id);
  if (button) {
    button.addEventListener('click', handler);
  }
}

bindClick('saveTokenBtn', saveToken);
bindClick('updateRequireApprovalBtn', updateRequireApproval);
bindClick('saveCollectionBtn', saveCollection);
bindClick('updateCacheEpochBtn', updateCacheEpoch);
bindClick('refreshCanvasBtn', refreshCanvas);
bindClick('startWarmupBtn', startWarmup);
bindClick('startCatalogWarmupBtn', startCatalogWarmup);
bindClick('pauseWarmupBtn', pauseWarmup);
bindClick('resumeWarmupBtn', resumeWarmup);
bindClick('loadWarmupStatsBtn', loadWarmupStats);
bindClick('loadCatalogWarmupBtn', loadCatalogWarmupStatus);
bindClick('startTokenWarmRangeBtn', startTokenWarmupRange);
bindClick('startTokenWarmManualBtn', startTokenWarmupManual);
bindClick('loadTokenWarmupBtn', loadTokenWarmupStatus);
bindClick('loadWarmupJobsBtn', loadWarmupJobs);
bindClick('loadCacheStatsBtn', loadCacheStats);
bindClick('purgeCollectionBtn', purgeCollection);
bindClick('purgeRendersBtn', purgeRenders);
bindClick('purgeAllBtn', purgeAll);
bindClick('loadHashReplacementsBtn', loadHashReplacements);
bindClick('uploadHashReplacementBtn', uploadHashReplacement);
bindClick('loadRpcBtn', loadRpc);
bindClick('loadRpcHealthBtn', loadRpcHealth);
bindClick('saveRpcBtn', saveRpc);
bindClick('createClientBtn', createClient);
bindClick('loadClientsBtn', loadClients);
bindClick('createClientKeyBtn', createClientKey);
bindClick('loadClientKeysBtn', loadClientKeys);
bindClick('createIpRuleBtn', createIpRule);
bindClick('loadIpRulesBtn', loadIpRules);
bindClick('loadUsageBtn', loadUsage);

(async function init() {
  try {
    await loadSettings();
    await loadCollections();
    await loadWarmupStats();
    await loadWarmupJobs();
    await loadCacheStats();
    await loadHashReplacements();
    await loadClients();
  } catch (err) {
    authStatus.textContent = 'Authentication required';
  }
})();
