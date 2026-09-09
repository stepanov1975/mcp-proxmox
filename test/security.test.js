import test from 'node:test';
import assert from 'node:assert/strict';
import { ProxmoxServer } from '../index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

const readTools = [
  'proxmox_get_nodes', 'proxmox_get_node_status', 'proxmox_get_vms',
  'proxmox_get_vm_status', 'proxmox_get_storage', 'proxmox_get_cluster_status',
  'proxmox_list_templates', 'proxmox_get_next_vmid', 'proxmox_generate_terraform',
  'proxmox_list_snapshots_vm', 'proxmox_list_snapshots_lxc', 'proxmox_list_backups',
  'proxmox_get_task_status', 'proxmox_get_vm_config', 'proxmox_whoami',
  'proxmox_get_guest_ips', 'proxmox_get_rrd_data', 'proxmox_get_pools',
  'proxmox_get_ha_resources', 'proxmox_get_firewall_rules',
].sort();

function makeServer(elevated = false) {
  process.env.PROXMOX_HOST = 'example.invalid';
  process.env.PROXMOX_TOKEN_VALUE = 'synthetic-api-secret';
  process.env.PROXMOX_ALLOW_ELEVATED = String(elevated);
  delete process.env.PROXMOX_NODE_ALLOWLIST;
  delete process.env.PROXMOX_VMID_ALLOWLIST;
  return new ProxmoxServer();
}

async function connect(t, server) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'offline-test', version: '1.0.0' });
  await server.server.connect(serverTransport);
  await client.connect(clientTransport);
  t.after(() => client.close());
  return client;
}

const args = {
  node: 'pve1', vmid: '100', storage: 'local', type: 'qemu',
  upid: 'UPID:pve1:00000001:00000001:00000001:qmstart:100:root@pam:',
};

function response(data, status = 200) {
  return { ok: status === 200, status, text: async () => JSON.stringify({ data }) };
}

function mockReads(server, calls) {
  server.fetch = async (url, options) => {
    calls.push({ url, method: options.method });
    assert.equal(options.method, 'GET');
    if (url.endsWith('/nodes')) return response([{ node: 'pve1', status: 'online', maxcpu: 4, cpu: 0.25 }]);
    if (url.includes('/cluster/resources')) return response([]);
    if (url.endsWith('/cluster/nextid')) return response(101);
    if (url.endsWith('/config')) return response({ cores: 2, memory: 1024, net0: 'virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0' });
    if (url.endsWith('/status') || url.endsWith('/status/current')) return response({ status: 'stopped', exitstatus: 'OK', uptime: 60 });
    if (url.includes('/network-get-interfaces')) return response({ result: [] });
    if (url.includes('/access/permissions')) return response({ '/': { 'Sys.Audit': 1 } });
    return response([]);
  };
}

test('discovery is exactly read-only; every hidden tool rejects direct MCP calls before IO', async t => {
  const server = makeServer();
  const client = await connect(t, server);
  const read = (await client.listTools()).tools.map(tool => tool.name).sort();
  assert.deepEqual(read, readTools);
  server.allowElevated = true;
  const all = (await client.listTools()).tools.map(tool => tool.name);
  assert.equal(all.length, 67);
  server.allowElevated = false;
  let calls = 0;
  server.fetch = async () => { calls++; throw new Error('unexpected IO'); };
  for (const name of all.filter(name => !read.includes(name))) {
    const result = await client.callTool({ name, arguments: args });
    assert.equal(result.isError, true, name);
    assert.equal(result.structuredContent.error, 'elevated_permissions_required', name);
  }
  assert.equal(calls, 0);
  assert.equal((await client.callTool({ name: 'proxmox_future_mutation' })).isError, true);
});

test('every advertised read tool works against GET-only offline responses', async t => {
  const server = makeServer();
  const client = await connect(t, server);
  const calls = [];
  mockReads(server, calls);
  for (const name of readTools) {
    const toolArgs = { ...args };
    // Terraform with no selected guests is a normal empty result.
    if (name === 'proxmox_generate_terraform') delete toolArgs.vmid;
    const result = await client.callTool({ name, arguments: toolArgs });
    assert.notEqual(result.isError, true, `${name}: ${JSON.stringify(result)}`);
  }
  assert.ok(calls.some(call => call.url.endsWith('/cluster/status')));
  assert.ok(calls.some(call => call.url.endsWith('/nodes/pve1/status')));
  assert.ok(calls.every(call => call.method === 'GET'));
});

test('readonly transport blocks all non-GET methods; elevated mode retains mutation', async t => {
  const server = makeServer();
  let calls = 0;
  server.fetch = async () => { calls++; return response('UPID:synthetic-task'); };
  for (const method of ['POST', 'PUT', 'DELETE', 'PATCH', 'post']) {
    await assert.rejects(server.proxmoxRequest('/nodes/pve1/qemu/100/status/start', method), /Read-only/);
  }
  assert.equal((await server.startVM('pve1', '100', 'qemu')).isError, true);
  assert.equal(calls, 0);
  server.allowElevated = true;
  const client = await connect(t, server);
  assert.notEqual((await client.callTool({ name: 'proxmox_start_vm', arguments: args })).isError, true);
  assert.equal(calls, 1);
});

test('validation, API denial and legacy failures carry isError', async t => {
  const server = makeServer(true);
  const client = await connect(t, server);
  server.fetch = async () => response('permission denied', 403);
  for (const name of ['proxmox_get_node_status', 'proxmox_get_nodes', 'proxmox_get_cluster_status', 'proxmox_list_templates', 'proxmox_start_vm']) {
    const result = await client.callTool({ name, arguments: args });
    assert.equal(result.isError, true, name);
    assert.match(result.content[0].text, /403/);
  }
  server.fetch = async url => url.endsWith('/nodes')
    ? response([{ node: 'pve1', status: 'online' }])
    : response('cluster status permission denied', 403);
  const clusterDenied = await client.callTool({ name: 'proxmox_get_cluster_status' });
  assert.equal(clusterDenied.isError, true, 'cluster-specific denial must not be swallowed');
  assert.match(clusterDenied.content[0].text, /403/);
  assert.equal((await client.callTool({ name: 'proxmox_get_node_status', arguments: { node: '../bad' } })).isError, true);
});

test('TLS verification is default-on and only exact false opts out', () => {
  for (const setting of [undefined, '', 'true', 'FALSE', 'typo', 'false']) {
    if (setting === undefined) delete process.env.PROXMOX_VERIFY_TLS;
    else process.env.PROXMOX_VERIFY_TLS = setting;
    const server = makeServer();
    assert.equal(server.httpsAgent.options.rejectUnauthorized, setting !== 'false');
  }
  delete process.env.PROXMOX_VERIFY_TLS;
});

test('credentials are redacted in API, parse, network errors and structured/resource output, not guest fields', async t => {
  const server = makeServer();
  const client = await connect(t, server);
  const secret = server.proxmoxTokenValue;
  for (const failure of ['http', 'parse', 'network']) {
    server.fetch = async () => {
      if (failure === 'network') throw Object.assign(new Error(`failed header PVEAPIToken=user@pam!test=${secret}`), { name: 'FetchError' });
      return { ok: failure !== 'http', status: 403, text: async () => `invalid ${secret} PVEAPIToken=user@pam!test=${secret}` };
    };
    await assert.rejects(server.proxmoxRequest('/nodes'), error => !error.message.includes(secret) && (failure === 'parse' ? error.message === 'Failed to parse Proxmox API response: invalid JSON' : error.message.includes('[REDACTED]')));
    const result = await client.callTool({ name: 'proxmox_get_nodes' });
    assert.equal(result.isError, true);
    assert.ok(!JSON.stringify(result).includes(secret));
  }
  const config = { cores: 2, net0: 'virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0', sshkeys: 'ssh-ed25519 example-public-key', cipassword: 'guest-password', description: `diagnostic ${secret}` };
  server.fetch = async () => response(config);
  const result = await client.callTool({ name: 'proxmox_get_vm_config', arguments: args });
  assert.equal(result.structuredContent.config.cipassword, 'guest-password');
  assert.equal(result.structuredContent.config.net0, config.net0);
  assert.equal(result.structuredContent.config.sshkeys, config.sshkeys);
  assert.ok(!JSON.stringify(result).includes(secret));
  const resource = await client.readResource({ uri: 'proxmox://nodes' });
  assert.ok(!JSON.stringify(resource).includes(secret));
  server.proxmoxTokenValue = 'synthetic/secret"with-escapes';
  const variants = [server.proxmoxTokenValue, encodeURIComponent(server.proxmoxTokenValue), JSON.stringify(server.proxmoxTokenValue).slice(1, -1)];
  for (const variant of variants) {
    assert.equal(server.redactCredentials(`diagnostic ${variant}`), 'diagnostic [REDACTED]');
  }
});
