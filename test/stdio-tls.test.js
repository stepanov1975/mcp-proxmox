import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { mkdtemp, readFile, writeFile, mkdir, copyFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

// execFile uses argument arrays, never a shell or interpolated shell commands.
const exec = promisify(execFile);
const root = dirname(dirname(fileURLToPath(import.meta.url)));
// Deliberately do not inherit Proxmox credentials or TLS policy from the runner.
function env(extra = {}) {
  return { PATH: process.env.PATH, PROXMOX_HOST: '127.0.0.1', PROXMOX_USER: 'test@pam', PROXMOX_TOKEN_NAME: 'offline', PROXMOX_TOKEN_VALUE: 'offline-only-token', ...extra };
}

async function clientFor(t, extra = {}) {
  const transport = new StdioClientTransport({ command: process.execPath, args: [join(root, 'index.js')], env: env(extra), stderr: 'pipe' });
  let stderr = '';
  transport.stderr.on('data', chunk => { stderr += chunk; });
  const client = new Client({ name: 'stdio-offline-test', version: '1.0.0' });
  await client.connect(transport);
  t.after(async () => {
    await client.close();
    assert.ok(!stderr.includes('offline-only-token'));
  });
  return client;
}

test('actual stdio SDK handshake, TLS default rejection, opt-out, custom CA and structured responses', { timeout: 30000 }, async t => {
  const dir = await mkdtemp(join(tmpdir(), 'proxmox-offline-tls-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const key = join(dir, 'key.pem');
  const cert = join(dir, 'cert.pem');
  await exec('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost']);
  const calls = [];
  const server = https.createServer({ key: await readFile(key), cert: await readFile(cert) }, (req, res) => {
    calls.push({ method: req.method, url: req.url });
    assert.equal(req.headers.authorization, 'PVEAPIToken=test@pam!offline=offline-only-token');
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ data: [{ node: 'pve1', status: 'online' }] }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const port = String(server.address().port);
  const rejected = await clientFor(t, { PROXMOX_PORT: port });
  assert.ok(rejected.getServerCapabilities().tools);
  assert.equal((await rejected.callTool({ name: 'proxmox_get_nodes' })).isError, true);
  assert.equal(calls.length, 0, 'untrusted certificate rejected before HTTP request');
  for (const settings of [{ PROXMOX_VERIFY_TLS: 'false' }, { NODE_EXTRA_CA_CERTS: cert }]) {
    const client = await clientFor(t, { PROXMOX_PORT: port, ...settings });
    const tools = await client.listTools();
    assert.ok(tools.tools.some(tool => tool.name === 'proxmox_get_node_status'));
    assert.ok(!tools.tools.some(tool => tool.name === 'proxmox_start_vm'));
    const result = await client.callTool({ name: 'proxmox_get_nodes' });
    assert.notEqual(result.isError, true);
    assert.equal(result.structuredContent.nodes[0].node, 'pve1');
    assert.match(result.content[0].text, /pve1/);
    const before = calls.length;
    assert.equal((await client.callTool({ name: 'proxmox_start_vm', arguments: { node: 'pve1', vmid: '100' } })).isError, true);
    assert.equal(calls.length, before);
  }
  assert.equal(calls.length, 2);
  assert.ok(calls.every(call => call.method === 'GET'));
});

test('parent .env is never loaded or allowed to override explicit process environment', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'proxmox-offline-env-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const app = join(dir, 'app');
  await mkdir(app);
  await copyFile(join(root, 'index.js'), join(app, 'index.js'));
  await writeFile(join(app, 'package.json'), '{"type":"module"}');
  await symlink(join(root, 'node_modules'), join(app, 'node_modules'));
  await writeFile(join(dir, '.env'), 'PROXMOX_HOST=parent.invalid\nPROXMOX_TOKEN_VALUE=parent-token\nPROXMOX_ALLOW_ELEVATED=true\nPROXMOX_VERIFY_TLS=false\n');
  const code = `import { ProxmoxServer } from ${JSON.stringify(pathToFileURL(join(app, 'index.js')).href)}; const s = new ProxmoxServer(); console.log(JSON.stringify({ host: s.proxmoxHost, elevated: s.allowElevated, tls: s.verifyTls }));`;
  const result = await exec(process.execPath, ['--input-type=module', '-e', code], { env: env() });
  assert.deepEqual(JSON.parse(result.stdout), { host: '127.0.0.1', elevated: false, tls: true });
  assert.equal(result.stderr, '');
  const missing = env();
  delete missing.PROXMOX_HOST;
  delete missing.PROXMOX_TOKEN_VALUE;
  await assert.rejects(exec(process.execPath, ['--input-type=module', '-e', code], { env: missing }), error => /PROXMOX_HOST environment variable is required/.test(error.stderr));
});
