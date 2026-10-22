# Terza validator

An independent validator for **Terza Inference**, the model API marketplace on the
Terza Bittensor subnet. It evaluates miner offers by buying from them through the
Terza gateway like any customer, scores quality, availability, latency and price,
and can submit weights on chain.

It needs no database access, no miner credentials and no coldkey. Anyone with a
registered validator hotkey and a funded Terza API key can run it.

> **Networks:** set `"network": "finney"` and `"netuid": 103` for Terza on Bittensor
> mainnet, or `"test"` for testnet. Each network's endpoint and genesis hash are pinned;
> the validator refuses any other chain.

## How it works

- **Offers** come from the gateway's signed public directory
  (`GET /api/public/validator-directory`). The payload is verified against pinned
  gateway Ed25519 keys (`GET /api/public/gateway-identity`), must be at most five
  minutes old and must name the same network and netuid as your configuration.
- **Probes** go through the gateway as ordinary paid requests with your own API key,
  pinned to one offer with the `X-Terza-Offer` header. Miners receive the same signed
  gateway request as for any buyer, so they cannot single out validator traffic. You
  pay quoted prices from your own Terza balance.
- Gateway-side refusals (400/401/402/403/429, for example an empty balance) are
  recorded as `inconclusive` and never count against a miner. 502 and
  `offer_unavailable` 503 count as availability failures.
- **Organic traffic:** the directory includes 24-hour gateway statistics per offer.
  Rejected usage receipts above 1% of requests, or a success rate below 90% once there
  are at least 20 attributable requests, fail the offer (see Scoring).
  These statistics come from the gateway; probe results are measured independently.
- **Usage-weighted rewards (prepared, disabled):** `USAGE_WEIGHT = 0`, so rewards
  depend only on probe quality. Enabling it is a scoring change with a `VERSION` bump.

It never uses customer prompts, upstream credentials or coldkey signing.

## What it measures

Three fresh synthetic tasks per offer per round: arithmetic, sorting and structured
extraction from an untrusted document containing an instruction-injection decoy.
Every request carries a random 96-bit nonce; only exact JSON with the correct
nonce, answer, model label and a completed finish reason passes. At most four offers
run concurrently, and requests to one hotkey are serialized. HTTPS addresses are
resolved, checked for public IPs and pinned per request; redirects and environment
proxies are not used. Each probe has a 60-second deadline (hard probes 120 seconds),
so occasionally slow reasoning responses are not counted as failures.

**Model-substitution checks.** About 40 hard probes per offer per day (large
multiplication, modular exponentiation, letter counting, string reversal, date
differences, k-th smallest, base 7, multi-step state chains, Caesar decoding) are
mixed into normal rounds. They are graded exactly, tracked per hotkey and model for
three days, and compared with `reference_profiles.json`:

- accuracy whose 95% upper bound is more than 0.15 below the reference → fails the gate;
- median reasoning tokens more than 3× above or below the reference → share halved;
- fewer than 20 answered hard probes, or no reference profile → no effect.

Reference profiles are calibrated from a trusted source with `calibrate.py`, never
from miners. Changing a profile requires a `VERSION` bump.

**Image, speech, transcription and video offers** are bought like any other request:
a 1024×1024 image, a one-sentence speech clip, the transcription of a one-second tone,
or a 5-second video at the cheapest quoted resolution. Images, speech and transcription
are probed about 6 times a day, video twice a day; a probe passes when the gateway
returns conforming output. They then pass the same gates and compete on price within
each model group. With at least 3 probes in 3 days, the latest within 12 hours (36 for
video).

**Media offers** are scored on availability and output conformance, not automated
quality. About 6 paid probes per offer per day use the cheapest settings the offer
declares. Availability and conformance must each be at least 90%; passing media
offers then compete on price like text offers.

### Scoring (version 5): quality gates, then price

An offer must pass **every** gate. Passing a gate earns no extra reward; failing any
gate scores zero.

- At least 9 samples in the evidence window from 3 rounds, 3 per task family, with a
  sample within two probe intervals (20 minutes by default).
- Accuracy of at least 75%.
- Availability of at least 90%.
- No usage-receipt fraud (rejections above 1% of requests), and at least 90% success
  on observed buyer traffic once there are 20 attributable requests.
- Hard-probe accuracy not clearly below the model's reference profile.
- Media offers: availability and output conformance of at least 90%.

Passing offers in a model cohort then share the cohort's budget **by price alone**.
Each offer's share is proportional to `min(median_quote / quote, 3)`: a median-priced
offer counts 1, a half-price offer 2, a double-price offer 0.5. The cap means quoting
below a third of the median earns nothing further. Quotes use a standard 512-input /
128-output token workload and are binding: the gateway charges buyers the quoted price
and routes them to the cheapest eligible offer. A reasoning-profile mismatch
(substitution suspicion) halves an offer's share.

Each offer is probed about once per `probe_interval_minutes` (default 10), and a round
never spends more than `round_budget_usd` (default 1); offers that do not fit wait for
the next round, oldest first. Set `models` to `"*"` to reward every model in the
directory, or to a list of model IDs. Each model is a cohort with an equal budget; only
cohorts with passing supply allocate rewards. Quote
changes invalidate older evidence. Expired, paused, suspended, unapproved or
unregistered offers and your own hotkey are excluded.


Evidence is kept in a private SQLite database in `state_dir`. No bearer token,
upstream origin or customer content is written to reports. An exclusive lock
prevents two workers sharing one state directory.

## Setup

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

1. Register a validator hotkey on the subnet with your own coldkey (`btcli`).
2. Create a Terza account, add balance and create an API key. Save it as
   `{"api_key": "..."}` in a mode-0600 file.
3. Save the hotkey password as `{"validator_hotkey_password": "..."}` in a mode-0600
   file. Only the hotkey is unlocked, never the coldkey.
4. Copy `config.example.json`, fill in the netuid, benchmark model IDs, the gateway
   public key from `https://terza.si/api/public/gateway-identity`, your hotkey address
   and file paths, and set the file to mode 0600.

Evaluate only (no chain writes):

```sh
.venv/bin/python terza_validator.py --config /etc/terza-validator/validator.json --watch
```

Evaluate and submit weights:

```sh
.venv/bin/python terza_validator.py --config /etc/terza-validator/validator.json --watch --submit
```

Latest metrics and proposed weights are written to `state_dir/latest.json`.
`terza-validator.service.example` is a hardened systemd unit for evaluation-only
operation; add the submit flag when you are ready.

## Chain protections

The RPC endpoint and genesis hash are pinned; fallback and archive endpoints are
disabled, and a chain reset fails closed. Before dispatch, membership is verified in
both directions at a finalized block. Before submission, offers and scores are
refreshed, then UID mapping, validator permit, weights version, rate limit and
minimum/maximum weight constraints are checked. Too few qualified miners blocks
submission; no uniform weights are invented for untested miners.

Bittensor SDK 11.3.0 `SetWeights` selects plaintext or commit-reveal from the subnet
configuration. The transaction policy restricts the netuid, forbids any token spend
and caps the fee at 0.01 TAO. Only weights are submitted: no transfers, staking,
registration or hyperparameter changes.

A `submitting` record is stored before signing. Rejections and interrupted
submissions are recorded as `unknown` and block further attempts until you check the
chain and reconcile the record. For commit-reveal,
`weight_activation=awaiting_chain_reveal` means the revealed weights have not yet
been observed.

## Limits

This is a text instruction-following benchmark plus media conformance checks, not a
full reasoning, coding, vision or audio quality evaluation. It does not prove a
model's identity, upstream provenance, honest token usage or the absence of
collusion. A miner may still recognize benchmark traffic; random tasks and nonces
reduce but do not remove that risk. Do not present these scores as model
verification.

## Tests

```sh
.venv/bin/python -m unittest -v
```

The tests cover replay and mismatch rejection, quality and freshness gates, price
bounds, quote revisions, private-address rejection, interrupted evidence, network
enforcement, UID handling, permits and rate limits, weight constraints and submission
receipts against a fake chain.
