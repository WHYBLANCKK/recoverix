# Recoverix — Zero-Cost ($0/Month) Staging Deployment Guide

This guide details the procedure for deploying Recoverix to publicly accessible hosting using exclusively **free-tier services ($0/month)**.

---

## 1. Selected Zero-Cost Architecture

```
User Browser (Phone / Laptop)
   ├── 1. Loads UI (0s cold start) ──> Vercel Hobby ($0) [Next.js Frontend]
   └── 2. Upload / Recovery / DL ───> Render Free ($0) [FastAPI Docker Backend]
                                          └── Ephemeral SQLite (/app/data/recoverix.db)
```

- **Frontend**: **Vercel Hobby Plan** ($0/month)
  - Serves the Next.js static site and React components via global CDN.
  - Zero cold starts for initial page visits.
  - Generous 100 GB/month bandwidth limit.
- **Backend**: **Render Free Web Service** ($0/month)
  - Runs the containerized Python/FastAPI recovery engine via `Dockerfile.backend`.
  - 750 free instance hours per month per workspace.
  - Includes free automatic TLS certificates on `onrender.com`.
- **Storage**: **Render Ephemeral SQLite Container Disk** ($0/month)
  - No external database or paid persistent disks required.
  - Ephemeral SQLite stores upload and recovery buffers during active user sessions.

---

## 2. Storage Model & Operational Limitations

### Ephemeral Storage Lifecycle
- Render free instances do not support persistent disks.
- Recovered files and SQLite metadata are stored at `/app/data/recoverix.db` on the container's temporary local filesystem.
- **When the container is idle for 15 minutes**, Render automatically spins the container down to 0 instances.
- Upon spin-down or restart, the temporary filesystem is wiped clean. A fresh, empty SQLite database is initialized when the service wakes up.
- **Session Duration**: The user upload, recovery, and download flow takes ~30–60 seconds. The 15-minute idle spin-down window provides ample time to download recovered files.
- **Explicit Privacy Alignment**: This fits Recoverix's built-in 24-hour privacy retention policy (`store.purge_expired_recovered_files(ttl_hours=24)`). Recoverix does not serve as a permanent file vault.

### Free-Tier Limitations
1. **Cold Starts (~45–60s)**:
   - When the backend has been idle for >15 minutes, the first recovery request takes 45–60 seconds while the free container spins up. Subsequent requests respond in 1–2 seconds.
2. **Download Link Lifespan**:
   - Download tokens (`rec_file_<uuid>`) are valid while the container remains active. If a user waits >15 minutes after recovery before downloading, the container may spin down, returning HTTP 404. In that event, the user can re-upload their file.
3. **Upload Size Ceiling**:
   - Strictly enforced at 5 MiB to ensure bounded memory usage within the 512 MB container limit.
4. **Rate Limiting**:
   - Enforced at 60 requests per minute per client IP address.

---

## 3. Pre-Flight Setup & Environment Variables

### A. Backend (Render Free Web Service)

| Variable | Recommended Value | Purpose |
| :--- | :--- | :--- |
| `RECOVERIX_DB_PATH` | `/app/data/recoverix.db` | Path to ephemeral SQLite database |
| `RECOVERIX_TRUSTED_PROXIES` | `private` | Trusts Render's internal private proxy mesh (`10.x.x.x`) for rate limiting while defending against client IP spoofing |
| `RECOVERIX_CORS_ORIGINS` | `https://<your-frontend-domain>` | Restricts CORS to the deployed frontend (e.g. `https://recoverix.vercel.app`) |
| `PYTHONUNBUFFERED` | `1` | Ensures immediate container log flushing |

### B. Frontend (Vercel Hobby)

| Variable | Value | Purpose |
| :--- | :--- | :--- |
| `NEXT_PUBLIC_API_URL` | `https://<your-backend>.onrender.com` | Base URL for backend API requests |

---

## 4. Step-by-Step Deployment Instructions

### Step 1: Deploy Backend to Render

1. Log into [dashboard.render.com](https://dashboard.render.com/).
2. Click **New +** → **Web Service**.
3. Connect your GitHub repository (`recoverix`) and select branch `recoverix/staging-candidate`.
4. Configure the service:
   - **Name**: `recoverix-backend`
   - **Runtime**: `Docker`
   - **Dockerfile Path**: `Dockerfile.backend`
   - **Docker Context**: `.`
   - **Instance Type**: **Free ($0/month)** *(Do not select Starter or attach a disk)*
5. Under **Advanced** → **Environment Variables**, add:
   - `RECOVERIX_DB_PATH` = `/app/data/recoverix.db`
   - `RECOVERIX_TRUSTED_PROXIES` = `private`
   - `PYTHONUNBUFFERED` = `1`
   - `RECOVERIX_CORS_ORIGINS` = `http://localhost:3000` *(You will update this with your Vercel URL in Step 3)*
6. Click **Create Web Service**.
7. Wait ~2–3 minutes for the build to finish. Verify backend health:
   ```bash
   curl https://<your-backend>.onrender.com/health
   # Expected response: {"status":"ok","service":"recoverix-api"}
   ```

### Step 2: Deploy Frontend to Vercel

1. Log into [vercel.com](https://vercel.com/).
2. Click **Add New...** → **Project**.
3. Import your GitHub repository (`recoverix`) on branch `recoverix/staging-candidate`.
4. Configure project settings:
   - **Framework Preset**: `Next.js`
   - **Root Directory**: `frontend`
5. In **Environment Variables**, add:
   - `NEXT_PUBLIC_API_URL` = `https://<your-backend>.onrender.com`
6. Click **Deploy**.
7. Note the assigned frontend URL (e.g., `https://recoverix-staging.vercel.app`).

### Step 3: Link CORS on Backend

1. Return to the Render dashboard for `recoverix-backend`.
2. Go to **Environment** and update:
   - `RECOVERIX_CORS_ORIGINS` = `https://<your-assigned-vercel-domain>`
3. Click **Save Changes** (Render will automatically redeploy the backend with the new CORS origin).

---

## 5. Verification & Testing

1. Open the Vercel URL in your browser (mobile or desktop).
2. Upload a damaged sample file across any of the 8 supported formats:
   - PDF, JSON, CSV, TXT, XML, PNG, JPEG, or ZIP.
3. Observe analysis results:
   - Verified bytes ($V$), Reconstructed bytes ($R$), and Missing bytes ($M$).
4. Click **Download Recovered File** and confirm the file is saved and valid.
5. Inspect the Network tab in Developer Tools:
   - Confirm requests hit `https://<your-backend>.onrender.com/api/recover-file`.
   - Confirm response headers include `access-control-allow-origin: https://<your-frontend-domain>`.

---

## 6. How to Avoid Incurring Any Charges

1. **Never attach a Render Disk**: In the Render settings, the "Disks" tab offers persistent block storage starting at $0.25/GB/month plus an automatic upgrade to the paid Starter compute tier ($7/month). Keep this empty.
2. **Never change the Instance Type from Free**: Ensure the compute plan remains set to **Free ($0/month)**.
3. **Monitor Instance Hours**: The 750 free instance hours per calendar month are more than sufficient for a single sleeping backend web service.
