import { afterEach, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { fileURLToPath, URL as NodeURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import process from 'node:process';

const root = fileURLToPath(new NodeURL('../../', import.meta.url));
const commands = ['dotnet restore onebighead.slnx',
  'dotnet test backend/tests/backend.tests/backend.tests.csproj --no-restore --verbosity minimal',
  'npm ci', 'npm run typecheck', 'npm run lint', 'npm run test:coverage', 'npm run build'];
const temporaryDirectories: string[] = [];
afterEach(() => { for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true }); });

function verify(failure = '') {
  const directory = mkdtempSync(join(tmpdir(), 'onebighead-verification-'));
  temporaryDirectories.push(directory);
  const log = join(directory, 'commands.jsonl');
  for (const tool of ['dotnet', 'npm']) {
    // Run the actual platform script with controlled tools: a failed gate must stop
    // the workflow before any later command can install, test or build anything.
    const program = `const fs = require('node:fs');
const command = [${JSON.stringify(tool)}, ...process.argv.slice(2)].join(' ');
fs.appendFileSync(process.env.VERIFY_LOG, JSON.stringify({command, cwd: process.cwd()}) + '\\n');
if (process.env.VERIFY_FAIL === command) process.exit(17);
`;
    if (process.platform === 'win32') {
      const runner = join(directory, `${tool}.cjs`);
      writeFileSync(runner, program);
      writeFileSync(join(directory, `${tool}.cmd`), `@node "${runner}" %*\r\n`);
    } else {
      writeFileSync(join(directory, tool), `#!/usr/bin/env node\n${program}`, { mode: 0o755 });
    }
  }
  const windows = process.platform === 'win32';
  const script = join(root, 'scripts', windows ? 'verify.ps1' : 'verify.sh');
  const result = spawnSync(windows ? 'pwsh' : 'bash', windows ? ['-NoProfile', '-File', script] : [script], {
    cwd: directory,
    env: { ...process.env, PATH: directory + delimiter + process.env.PATH, VERIFY_LOG: log, VERIFY_FAIL: failure },
    encoding: 'utf8', timeout: 15000,
  });
  const calls = existsSync(log) ? readFileSync(log, 'utf8').trim().split('\n').map(line => JSON.parse(line) as { command: string; cwd: string }) : [];
  return { result, calls };
}

it('runs compilation checks, full backend tests and the frontend coverage gate before building', () => {
  const { result, calls } = verify();
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).toBe(0);
  expect(calls.map(call => call.command)).toEqual(commands);
  expect(calls.map(call => call.cwd)).toEqual(commands.map((_, index) => index < 2 ? root.replace(/[\\/]$/, '') : join(root, 'frontend')));
});

it.each(commands)('stops verification immediately when %s fails', failure => {
  const { result, calls } = verify(failure);
  expect(result.error).toBeUndefined();
  expect(result.status).not.toBe(0);
  expect(calls.map(call => call.command)).toEqual(commands.slice(0, commands.indexOf(failure) + 1));
});
