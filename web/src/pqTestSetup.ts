// Exercise the actual pinned Go WASM in Node, without a mock crypto implementation.
import { readFileSync } from 'node:fs';
import { runInThisContext } from 'node:vm';

runInThisContext(readFileSync(new URL('../.pq/wasm_exec.js', import.meta.url), 'utf8'));
const go = new Go();
const { instance } = await WebAssembly.instantiate(readFileSync(new URL('../.pq/pq.wasm', import.meta.url)), go.importObject);
void go.run(instance);
if (!globalThis.pqwasm) throw new Error('pqwasm did not start');
