#!/usr/bin/env node
/**
 * Checks a Storeware price record without trusting Storeware.
 *
 *   node verify.mjs <variant id, or the record's URL>
 *   node verify.mjs --file record.json
 *
 * One file, Node 20 or later, nothing to install, no Storeware code. It fetches
 * a record and checks it four ways: the figures against their commitments, the
 * chain from the first entry, the tree from the newest entry to the root, and
 * the root against the log's signature.
 *
 *   0  every check held, and every date over three days old has a stamp behind it
 *   1  a check failed: the record does not hold
 *   3  every check held, but some dates are the log's own claim
 *
 * It reads the outside timestamps and holds each entry's date to them, but it
 * does not check an authority's own signature, because that means choosing whose
 * certificates to trust. See README.md for the `openssl` line.
 */
import { createHash, createPublicKey, verify as ed25519Verify } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/** The log's name and key. Pinned here, never read from the record. */
export const ORIGIN = 'storeware.ai/price-record';
export const PUBLIC_KEY = 'vP_5IEr3wODGjqwdMQl7D-7qIpZoFvIl044eN-WmST4';
const API = 'https://api.storeware.ai';

const sha256 = (...parts) => {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
};

/** RFC 6962: the domain prefixes stop a leaf being passed off as a node. */
const leafHash = (bytes) => sha256(Buffer.from([0x00]), bytes);
const nodeHash = (left, right) => sha256(Buffer.from([0x01]), left, right);

/** RFC 9162, 2.1.3.2. */
export function verifyInclusion(hash, index, size, proof, root) {
  if (index < 0 || index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = hash;
  for (const p of proof) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && r.equals(root);
}

/** RFC 9162, 2.1.4.2. */
export function verifyConsistency(first, second, proof, firstRoot, secondRoot) {
  if (first < 1 || first > second) return false;
  if (first === second) return proof.length === 0 && firstRoot.equals(secondRoot);

  const path = (first & (first - 1)) === 0 ? [firstRoot, ...proof] : [...proof];
  if (path.length === 0) return false;

  let fn = first - 1;
  let sn = second - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  let fr = path[0];
  let sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && fr.equals(firstRoot) && sr.equals(secondRoot);
}

/** A C2SP signed note, read against the pinned key. Returns the size and root. */
export function readHead(note) {
  const [text, signatures] = note.split('\n\n');
  const body = `${text}\n`;
  const lines = body.split('\n');
  if (lines[0] !== ORIGIN) throw new Error(`this head is from another log: ${lines[0]}`);

  const raw = Buffer.from(PUBLIC_KEY, 'base64url');
  const keyHash = sha256(`${ORIGIN}\n`, Buffer.from([0x01]), raw).subarray(0, 4);
  const key = createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: PUBLIC_KEY },
    format: 'jwk',
  });

  const signed = (signatures ?? '').split('\n').some((line) => {
    const prefix = `— ${ORIGIN} `;
    if (!line.startsWith(prefix)) return false;
    const bytes = Buffer.from(line.slice(prefix.length), 'base64');
    return (
      bytes.subarray(0, 4).equals(keyHash) &&
      ed25519Verify(null, Buffer.from(body), key, bytes.subarray(4))
    );
  });
  if (!signed) throw new Error('the head is not signed by the log’s key');

  return { size: Number(lines[1]), root: Buffer.from(lines[2], 'base64') };
}

/** RFC 8785 for these values: strings, integers and null, with sorted keys. */
function canonical(values) {
  const sorted = Object.keys(values)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${JSON.stringify(values[key])}`);
  return `{${sorted.join(',')}}`;
}

/** How long before its first stamp an entry's date still counts as confirmed. */
const STAMP_WINDOW_MS = 3 * 24 * 60 * 60 * 1000;
const CLOCK_SLACK_MS = 5 * 60 * 1000;

/**
 * When an RFC 3161 reply says it was issued, if it covers this head.
 *
 * Reads the first GeneralizedTime, which is the stamp's own: its certificates
 * come after it. Does not check the authority's signature.
 */
export function stampTime(token, checkpoint) {
  const reply = Buffer.from(token, 'base64');
  if (!reply.includes(sha256(checkpoint))) return null;
  // eslint-disable-next-line no-control-regex -- DER tags are control characters.
  const found = /\x18([\x0f-\x18])(\d{14}(?:\.\d{1,9})?Z)/.exec(reply.toString('latin1'));
  if (!found || found[1].charCodeAt(0) !== found[2].length) return null;
  const t = found[2];
  const iso = `${t.slice(0, 4)}-${t.slice(4, 6)}-${t.slice(6, 8)}T${t.slice(8, 10)}:${t.slice(10, 12)}:${t.slice(12, 14)}Z`;
  return Date.parse(iso) || null;
}

/**
 * Holds each entry's date to the first stamped head it is in.
 *
 * Late is not false: an outage makes honest entries late, so a date too far
 * before its stamp, or an old entry with no stamp, is counted as unconfirmed
 * rather than refused. An entry dated after a stamp that holds it is impossible,
 * and that is refused. The latest of a head's stamps is used, so one forged stamp
 * cannot pull a date back alone.
 */
function checkDates(series, stampedHeads, read, now) {
  let covered = 0;
  let unconfirmed = 0;

  for (const witness of series.witnesses ?? []) {
    const stamped = stampedHeads.find((one) => one.tree_size === witness.tree_size);
    if (!stamped) throw new Error('a witness names a head that was not given');

    const tree = read(stamped.checkpoint);
    const entry = series.entries[witness.seq];
    if (!entry) throw new Error(`a witness names an entry that is not here`);

    const proof = witness.inclusion_proof.map((hash) => Buffer.from(hash, 'hex'));
    const hash = leafHash(Buffer.from(entry.payload));
    if (!verifyInclusion(hash, witness.leaf_index, tree.size, proof, tree.root)) {
      throw new Error(`entry ${witness.seq} is not in the stamped tree`);
    }

    const times = stamped.anchors
      .map((anchor) => stampTime(anchor.token, stamped.checkpoint))
      .filter(Boolean);
    if (times.length === 0) throw new Error('a stamped head has no stamp that covers it');
    const stampedAt = Math.max(...times);

    for (; covered <= witness.seq; covered++) {
      const at = Date.parse(JSON.parse(series.entries[covered].payload).at);
      if (at > stampedAt + CLOCK_SLACK_MS) {
        throw new Error(`entry ${covered} is dated after its stamp`);
      }
      if (stampedAt - at > STAMP_WINDOW_MS) unconfirmed++;
    }
  }

  for (let i = covered; i < series.entries.length; i++) {
    const at = Date.parse(JSON.parse(series.entries[i].payload).at);
    if (now - at > STAMP_WINDOW_MS) unconfirmed++;
  }

  return { dated: covered, unconfirmed };
}

/** Every check on one currency of a record. Throws on the first that fails. */
export function checkSeries(head, series, stampedHeads = [], read = readHead, now = Date.now()) {
  let previous = null;
  let lastAt = null;

  series.entries.forEach((entry, i) => {
    const bytes = Buffer.from(entry.payload);
    const header = JSON.parse(entry.payload);

    if (header.seq !== i) throw new Error(`entry ${i} says it is entry ${header.seq}`);
    if (header.series !== series.series) throw new Error(`entry ${i} is from another series`);
    if ((previous?.toString('hex') ?? null) !== header.prev) {
      throw new Error(`entry ${i} does not name the entry before it, so something was removed`);
    }
    if (lastAt !== null && header.at < lastAt) {
      throw new Error(`entry ${i} is dated before the entry before it`);
    }
    lastAt = header.at;

    if (header.listed && !entry.revealed) {
      throw new Error(`entry ${i} hides a price that was on sale`);
    }

    if (entry.revealed) {
      const { salt, values } = entry.revealed;
      const opened = sha256(Buffer.from(salt, 'hex'), canonical(values)).toString('hex');
      if (opened !== header.commit) throw new Error(`entry ${i} shows other figures`);
      const named = sha256(`${values.variant_id}:${values.currency}`).toString('hex');
      if (named !== series.series) throw new Error(`entry ${i} is for another product`);
    }

    previous = leafHash(bytes);
  });

  if (!previous) throw new Error('there are no entries');

  const proof = series.inclusion_proof.map((hash) => Buffer.from(hash, 'hex'));
  if (!verifyInclusion(previous, series.latest_leaf_index, head.size, proof, head.root)) {
    throw new Error('the newest entry is not in the signed tree');
  }

  return checkDates(series, stampedHeads, read, now);
}

async function main() {
  const args = process.argv.slice(2);
  let record;
  let asked = null;

  if (args[0] === '--file') {
    record = JSON.parse(readFileSync(args[1], 'utf8'));
  } else if (args[0]) {
    asked = args[0].startsWith('http') ? args[0].split('/').pop() : args[0];
    const url = args[0].startsWith('http')
      ? args[0]
      : `${API}/api/price-record/variants/${args[0]}`;
    const response = await fetch(url);
    if (!response.ok) throw new Error(`${url} answered ${response.status}`);
    record = await response.json();
  } else {
    console.error('Usage: node verify.mjs <variant id or URL> | --file record.json');
    process.exit(2);
  }

  if (asked && record.variant_id !== asked) {
    throw new Error(`asked for ${asked} and was given ${record.variant_id}`);
  }
  if (!Array.isArray(record.series) || record.series.length === 0) {
    throw new Error('the record holds no series, so there is nothing to check');
  }

  let claimed = 0;
  const head = readHead(record.head.checkpoint);
  console.log(`Head: ${head.size} entries in the log, signed by the log’s key.`);

  for (const series of record.series) {
    const expected = sha256(`${record.variant_id}:${series.currency}`).toString('hex');
    if (series.series !== expected)
      throw new Error(`the ${series.currency} series is for another product`);

    const { dated, unconfirmed } = checkSeries(head, series, record.stamped_heads ?? []);
    claimed += unconfirmed;
    const shown = series.entries.filter((entry) => entry.revealed).length;
    console.log(
      `${series.currency}: ${series.entries.length} entries, unbroken, in the tree, ${shown} with figures shown, ${dated} covered by a stamp (signature not checked here), ${unconfirmed} with an unconfirmed date.`,
    );
    for (const entry of series.entries) {
      const { at, listed } = JSON.parse(entry.payload);
      const values = entry.revealed?.values;
      console.log(
        `  ${at}  ${listed ? `${values.amount} (was ${values.compare_at_amount})` : 'not on sale'}`,
      );
    }
  }

  console.log('Every check above held.');
  console.log('Not checked here: each authority’s signature on its stamp (see README.md),');
  console.log('and whether later entries exist. Compare with a head you kept to see a rewrite.');

  if (claimed > 0) {
    console.log(`${claimed} dates have no outside stamp to back them, so they are only claims.`);
    process.exitCode = 3;
  }
}

const ran =
  process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));

if (ran) {
  main().catch((error) => {
    console.error(`REFUSED: ${error.message}`);
    process.exit(1);
  });
}
