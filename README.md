<!--
  This repository is generated from the Storeware monorepo, where this package
  is developed at examples/price-record. It is a published artefact rather than the
  working copy, so a change made here is lost on the next release.

  Issues are read and very welcome. If you want to send a patch, open an issue
  first and we will point you at how it lands upstream -- that is a real answer
  rather than a deflection, and it saves you an afternoon of work on a tree that
  is overwritten.
-->

# Storeware price record: check it yourself

Every shop on [Storeware](https://storeware.ai) keeps a public record of the prices it offered, so a "was" price can be checked instead of believed. This repository is how you check it without trusting Storeware.

```bash
node verify.mjs <variant id>
```

Node 20 or later. Nothing to install. No Storeware code. Exit code 0 means every check held and every date over three days old has a stamp behind it. 3 means every check held but some dates are only the log's claim. 1 means the record does not hold.

It checks five things:

1. **The figures.** Shown prices match the commitments in the entries, and no entry listed for sale hides its price.
2. **The chain.** Each entry names the one before, so none can be taken out of the middle.
3. **The tree.** The newest entry reaches the root of an RFC 6962 Merkle tree.
4. **The head.** The root is signed by the log's Ed25519 key, pinned in `verify.mjs`.
5. **The dates.** Each entry's date is compared with the first outside stamp covering it. One dated after that stamp is refused. One more than three days before it, or an old entry with no stamp, is reported as unconfirmed. An outage makes honest dates late, so this weakens a date and does not call it false. It rests on the stamps being real, which is the check below.

## The stamps

Each day the newest head goes to two RFC 3161 timestamp authorities, who see only a hash. `verify.mjs` reads their replies but does not check the authority's own signature, because that means choosing whose certificates to trust. To do that:

```bash
curl -s https://api.storeware.ai/api/price-record/head > head.json
node -e "process.stdout.write(JSON.parse(require('fs').readFileSync('head.json')).stamped.checkpoint)" > head.txt
node -e "process.stdout.write(Buffer.from(JSON.parse(require('fs').readFileSync('head.json')).stamped.anchors[0].token,'base64'))" > stamp.tsr
openssl ts -reply -in stamp.tsr -text
openssl dgst -sha256 head.txt
```

The message data in the reply is the digest of `head.txt`. Add `openssl ts -verify` with the authority's certificates to check its signature.

## What a rewrite would take, and who would see it

Stamps date a head. They do not stop Storeware building a different tree and having that stamped today. What such a rewrite cannot do is match a head somebody already kept. So the record is tamper-evident to anybody who keeps a head, and the more who do, the stronger it is.

`watch.mjs` keeps every head it sees on the `heads` branch here, hourly, and fails if a new head does not extend the last. This repository is run by Storeware, so it is a convenience and not an independent witness. To be one, run `watch.mjs` yourself.

## What this does not prove

- The record shows the price and the "was" price while a thing was listed for sale, in stock or not. It does not show that anybody paid that price.
- It does not cover discount codes, basket offers or agreed trade prices.
- It cannot show that a later entry was not left out. Nothing in a head says how long a series is.
- A product deleted and made again starts a new record, and so does one imported from another platform.
- A shop can switch off showing its record, and the record answers 404 while it is off.
- Deleting a shop removes its figures for good. Only the hashes stay.

The format is described at [storeware.ai/docs/agents/price-record](https://storeware.ai/docs/agents/price-record).
