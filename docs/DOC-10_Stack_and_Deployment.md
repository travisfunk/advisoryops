# DOC-10 — Stack and Deployment (MVP)
## Locked MVP Stack (Decision)
- Backend runtime: **Python**
- API framework: **FastAPI**
- Deployment shape: **Monolith container** (API + worker code in same repo; deploy as one or two processes)
- Hosting (MVP): **Railway**
- Scheduler: **Railway Cron Jobs**
- Job execution model: **Postgres-backed queue + worker**
- Database (prod MVP): **Postgres**
- Object storage: **Cloudflare R2** (S3-compatible API)
## Why this stack
- Minimizes operational overhead during MVP
- Strong ecosystem for parsing/PDF/text normalization + LLM extraction
- Portable architecture: container + S3-compatible storage makes later migration straightforward
## Scale-up path (later)
- Queue: Postgres queue → managed queue (Cloud Tasks/PubSub/SQS/CF Queues)
- Hosting: Railway → Cloud Run/AWS (no architecture rewrite)
- Add UI separately (optional TS frontend)
