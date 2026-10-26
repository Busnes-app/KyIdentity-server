// Builds results.csv (one row per before/after capture pair) and checks.csv (in-app
// verification) from the manifests in screenshots/. Usage: node results.mjs
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { here } from './capture-core.mjs';

const dir = here(import.meta.url);
const shots = join(dir, 'screenshots');
const read = (f) => JSON.parse(readFileSync(join(shots, f), 'utf8'));
const csv = (rows) => rows.map((r) => r.map((v) => `"${String(v ?? '').replaceAll('"', '""')}"`).join(',')).join('\n') + '\n';
const manifests = readdirSync(shots).filter((f) => f.endsWith('-manifest.json')).map(read);
const key = (f) => `${f.surface}|${f.viewport}|${f.theme}`;
const before = manifests.find((m) => m.prefix.endsWith('-00-before'));
const rows = [['product', 'stage', 'surface', 'viewport', 'theme', 'before_file', 'before_head', 'before_sha256', 'after_file', 'after_head', 'after_diff_sha256', 'after_sha256', 'after_overflow_px', 'driver', 'captured', 'previous_file', 'previous_sha256']];
for (const after of manifests.filter((m) => m !== before)) {
  for (const f of after.files) {
    const b = before?.files.find((x) => key(x) === key(f));
    // The latest earlier batch that captured the same view, e.g. stage 02 for stage 03.
    const prev = manifests.filter((m) => m.captured < after.captured).sort((x, y) => (x.captured < y.captured ? 1 : -1)).map((m) => m.files.find((x) => key(x) === key(f))).find(Boolean);
    rows.push([after.product, after.prefix.split('-')[1], f.surface, f.viewport, f.theme, b?.file ?? 'none (new surface)', before?.head, b?.sha256, f.file, after.head, after.uncommitted_diff_sha256, f.sha256, f.overflow_px, after.driver, after.captured, prev?.file, prev?.sha256]);
  }
}
writeFileSync(join(dir, 'results.csv'), csv(rows));
const checks = [['product', 'prefix', 'head', 'diff_sha256', 'check', 'result', 'detail']];
for (const f of readdirSync(shots).filter((f) => f.endsWith('-verify.json'))) {
  const v = read(f);
  for (const r of v.results) checks.push([v.product, v.prefix, v.head, v.uncommitted_diff_sha256, r.name, r.ok ? 'pass' : 'fail', JSON.stringify(r.detail)]);
}
writeFileSync(join(dir, 'checks.csv'), csv(checks));
console.log(`results.csv ${rows.length - 1} rows, checks.csv ${checks.length - 1} rows`);
