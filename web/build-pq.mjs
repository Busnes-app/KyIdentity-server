// Build the pinned Go implementation and matching runtime; never vendor a WASM binary.
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const web = fileURLToPath(new URL('.', import.meta.url));
const root = fileURLToPath(new URL('..', import.meta.url));
const output = join(web, '.pq');
mkdirSync(output, { recursive: true });
// Match the shipping image, including hosts with a locally patched Go toolchain.
const goEnv = { ...process.env, GOTOOLCHAIN: 'go1.27.4', GOEXPERIMENT: '' };
execFileSync('go', ['build', '-trimpath', '-o', join(output, 'pq.wasm'),
  'github.com/Busnes-app/ky-primitives/cmd/pqwasm'], {
  cwd: root, env: { ...goEnv, GOOS: 'js', GOARCH: 'wasm', CGO_ENABLED: '0' }, stdio: 'inherit',
});
const goroot = execFileSync('go', ['env', 'GOROOT'], { cwd: root, env: goEnv, encoding: 'utf8' }).trim();
rmSync(join(output, 'wasm_exec.js'), { force: true });
copyFileSync(join(goroot, 'lib/wasm/wasm_exec.js'), join(output, 'wasm_exec.js'));
const primitives = JSON.parse(execFileSync('go', ['list', '-m', '-json', 'github.com/Busnes-app/ky-primitives'],
  { cwd: root, env: goEnv, encoding: 'utf8' }));
rmSync(join(output, 'vectors.json'), { force: true });
copyFileSync(join(primitives.Dir, 'xwing/testdata/vectors.json'), join(output, 'vectors.json'));
