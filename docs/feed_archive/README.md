# AdvisoryOps full feed archive

`feed_latest.json` is intentionally bounded for fast GitHub Pages dashboard loading. The complete full-fidelity corpus is preserved in the JSONL shards in this directory. `manifest.json` records the shard count, record counts, byte sizes, SHA-256 hashes, and partition strategy. Shard membership is deterministic: `uint32_be(sha256(issue_id)[:4]) mod shard_count`.

This design keeps every published file well below GitHub's single-file limit while preserving an auditable, reconstructable historical baseline.
