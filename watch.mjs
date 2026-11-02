#!/usr/bin/env node
/**
 * Keeps a copy of the log's tree heads, and refuses one that rewrites history.
 *
 * Run hourly by `.github/workflows/watch.yml`, which commits `heads/` to the
 * `heads` branch. The value is in who runs it: this repository is run by
 * Storeware, so the copy here is a convenience. Run it yourself and it is a
 * witness, because a rewrite cannot match a head you kept.
 *
 * A kept head is never replaced. A served head may add stamps to one, only if
 * its signed note is byte for byte the one kept.
 */
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readHead, verifyConsistency } from './verify.mjs';

const API = process.env.PRICE_RECORD_API ?? 'https://api.storeware.ai';
const DIR = process.env.PRICE_RECORD_HEADS ?? 'heads';

async function getJson(path) {
  const response = await fetch(`${API}${path}`);
  if (!response.ok) throw new Error(`${path} answered ${response.status}`);
  return response.json();
}

function keptSizes(dir) {
  return readdirSync(dir)
    .map((name) => Number(name.replace('.json', '')))
    .filter(Number.isSafeInteger)
    .sort((a, b) => a - b);
}

function held(dir, size) {
  const file = join(dir, `${size}.json`);
  return existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : null;
}

/** Keeps a head that has been proved, and refuses any other copy of the same size. */
function keep(dir, head) {
  const { stamped: _stamped, ...bare } = head;
  const already = held(dir, bare.tree_size);

  if (already && already.checkpoint !== bare.checkpoint) {
    throw new Error(`two different heads at size ${bare.tree_size}: the log forked`);
  }
  if (!already || already.anchors.length < bare.anchors.length) {
    writeFileSync(join(dir, `${bare.tree_size}.json`), `${JSON.stringify(bare, null, 2)}\n`);
  }
}

/** That `older` is the start of `newer`, by proof from the log. */
async function prove(older, newer, get) {
  if (older.size === newer.size) {
    if (!older.root.equals(newer.root)) {
      throw new Error(`two different heads at size ${older.size}: the log forked`);
    }
    return;
  }
  const { proof } = await get(`/api/price-record/consistency?from=${older.size}&to=${newer.size}`);
  const hashes = proof.map((hash) => Buffer.from(hash, 'hex'));
  if (!verifyConsistency(older.size, newer.size, hashes, older.root, newer.root)) {
    throw new Error(`the head at ${newer.size} rewrites the head at ${older.size}`);
  }
}

export async function watch({ dir = DIR, get = getJson, read = readHead } = {}) {
  mkdirSync(dir, { recursive: true });

  const published = await get('/api/price-record/head');
  const head = read(published.checkpoint);

  const newest = keptSizes(dir).at(-1);
  if (newest !== undefined) {
    if (head.size < newest) throw new Error(`the log shrank from ${newest} to ${head.size}`);
    await prove(read(held(dir, newest).checkpoint), head, get);
  }

  if (published.stamped) {
    const stamped = read(published.stamped.checkpoint);
    await prove(stamped, head, get);
    keep(dir, published.stamped);
  }

  keep(dir, published);
  return head.size;
}

const ran =
  process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));

if (ran) {
  const size = await watch();
  console.log(`Kept the head at ${size}.`);
}
