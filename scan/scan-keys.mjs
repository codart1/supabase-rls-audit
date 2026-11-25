#!/usr/bin/env node
// Finds Supabase keys that must never ship to the browser.
// Point it at a repo or at a built frontend (dist/, .next/, build/):
//   node scan/scan-keys.mjs ./dist
// Flags:
//   * legacy JWT keys whose payload says role=service_role
//   * new-style secret keys (sb_secret_...)
// The anon / publishable key is reported for information only: it is meant
// to be public, and is safe only if RLS is correct.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';

const root = process.argv[2] ?? '.';
const SKIP = new Set(['node_modules', '.git']);
const EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.html', '.json', '.env', '.map', '']);
const JWT = /eyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}/g;
const SECRET = /sb_secret_[\w-]{10,}/g;

let bad = 0;
function* walk(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const p = join(dir, name);
    const s = statSync(p);
    if (s.isDirectory()) yield* walk(p);
    else if (s.size < 20e6 && (EXT.has(extname(name)) || name.startsWith('.env'))) yield p;
  }
}
for (const file of walk(root)) {
  const text = readFileSync(file, 'utf8');
  for (const m of text.matchAll(JWT)) {
    let role = '?';
    try { role = JSON.parse(Buffer.from(m[0].split('.')[1], 'base64url')).role ?? '?'; } catch {}
    if (role === 'service_role') { bad++; console.log(`CRITICAL ${file}: service_role key (bypasses all RLS)`); }
    else console.log(`info     ${file}: JWT with role=${role}`);
  }
  for (const _ of text.matchAll(SECRET)) { bad++; console.log(`CRITICAL ${file}: sb_secret_ key`); }
}
console.log(bad ? `\n${bad} secret key(s) found` : '\nno secret keys found');
process.exit(bad ? 1 : 0);
