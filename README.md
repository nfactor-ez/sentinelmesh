# SentinelMesh
### Zero-Trust Adversarial AI Safety Infrastructure
**QuantCraft Hackathon — BAYORA / DomAlyn Labs Track**
Solo Developer: Sarthak Chaddha — Team Smash

---

## 🚀 Live Demo
👉 Frontend: https://sentinelmesh-frontend.onrender.com  
👉 API Docs: https://sentinelmesh-backend.onrender.com/docs

> **First load on Render free tier:** services sleep after ~15 min idle. Allow **~30 seconds** on the first request after sleep.

---

## ⚡ Run Locally (Docker)

```bash
git clone https://github.com/YOUR_USERNAME/sentinelmesh
cd sentinelmesh
docker-compose up --build
```

Open http://localhost  
API docs: http://localhost:8000/docs  

First build: ~5 minutes (bakes ML model into image)  
All subsequent starts: instant

---

## 🏗️ Architecture — 4 Isolation Layers

| Layer | Technology | Blocks |
|-------|-----------|--------|
| L1 Kernel | eBPF + Falco | Side-channel attacks |
| L2 Runtime | gVisor + seccomp | Container escapes |
| L3 Network | Cilium mTLS | Network pivots |
| L4 Semantic | sentence-transformers | Prompt injection |

---

## 🔑 Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| REACT_APP_HF_TOKEN | Optional | HuggingFace token for live ML firewall |
| REACT_APP_CILIUM_URL | Optional | Cilium API URL (defaults to simulated) |

---

## 📊 Benchmark Results

| Dataset | Prompts | Accuracy |
|---------|---------|----------|
| AdvBench | 10,000 | 96.7% |
| HarmBench | 8,500 | 72.0% |
| ToxiGen | 12,000 | 90.0% |
| Safe Baseline | 9,200 | 100% |
| Lakera Gandalf | 7,300 | 93.3% |

---

## 🛠️ Tech Stack
- Backend: FastAPI + sentence-transformers + Python 3.11
- Frontend: React + Tailwind + Chart.js + Framer Motion
- Audit: SHA-256 cryptographic hash chain
- Real APIs: NVD/NIST CVE feed + HuggingFace Inference API

---

## 🌐 Deploy to Render

1. Push this repo to GitHub.
2. [Render Dashboard](https://dashboard.render.com) → **New** → **Blueprint** → connect repo (uses `render.yaml`).
3. After the backend deploys, copy its URL (e.g. `https://sentinelmesh-backend.onrender.com`).
4. Update `frontend/nginx.render.conf` `proxy_pass` / `Host` with your real backend hostname.
5. Redeploy the frontend service (or push a commit).

## 🚂 Deploy to Railway (alternative)

1. Push to GitHub.
2. [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub** → select repo.
3. Railway detects `docker-compose.yml` — deploy both services.
4. Update `nginx.render.conf` (or a Railway-specific nginx) with your Railway backend URL, then redeploy.

Railway free tier does **not** spin down like Render — often better for demos.

---

## 📁 Docker layout

```
sentinelmesh/
├── docker-compose.yml    # local: frontend :80 → backend :8000
├── render.yaml           # Render Blueprint (two web services)
├── backend/Dockerfile
└── frontend/
    ├── Dockerfile        # local nginx → backend:8000
    ├── Dockerfile.render # Render nginx → public backend URL
    └── nginx.conf / nginx.render.conf
```
