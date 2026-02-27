# OASIS Challenges - Deployment Checklist

**Purpose:** Enable PR #22 (Challenge Registry + Docker) in the main OASIS repo

---

## ✅ Prerequisites (Already Done)

- [x] 15 challenges created and tested
- [x] GitHub Actions workflows for building images (`build-challenges.yml`, `publish-images.yml`)
- [x] Open-source readiness complete
- [x] `index.json` generator script created (`scripts/generate-index.js`)
- [x] Auto-generate workflow created (`.github/workflows/generate-index.yml`)

---

## 🚀 Deployment Steps

### Step 1: Make Repository Public ⚠️ REQUIRED FIRST

```bash
# Via GitHub UI
# Settings → General → Danger Zone → Change visibility → Make public
```

**Why:**
- GHCR packages must be public for unauthenticated pulls
- index.json must be accessible via raw.githubusercontent.com
- GitHub Actions GITHUB_TOKEN can publish packages

**Verify:**
```bash
curl https://github.com/KryptSec/oasis-challenges
# Should not require authentication
```

---

### Step 2: Generate index.json

```bash
cd /path/to/oasis-challenges
node scripts/generate-index.js
git add index.json
git commit -m "chore: add challenge registry index"
git push
```

**Verify:**
```bash
curl https://raw.githubusercontent.com/KryptSec/oasis-challenges/main/index.json
# Should return JSON with challenges array
```

---

### Step 3: Build & Publish Challenge Images to GHCR

**Option A: Manual trigger (recommended for first run)**
```bash
# Via GitHub UI
# Actions → Build and Push Challenge Images → Run workflow
```

**Option B: Push to trigger**
```bash
# Workflows trigger on push to main affecting challenge files
git push  # If there are pending changes
```

**Verify:**
```bash
# Check GHCR packages page
open https://github.com/orgs/KryptSec/packages

# Try pulling an image
docker pull ghcr.io/kryptsec/proxy-auth-bypass:latest
```

---

### Step 4: Build & Publish oasis-kali Image

**Create Dockerfile for oasis-kali:**
```bash
# In oasis-kali repo root
cat > Dockerfile <<'EOF'
FROM kalilinux/kali-rolling:latest

RUN apt-get update && apt-get install -y \
    curl \
    nmap \
    sqlmap \
    gobuster \
    nikto \
    python3 \
    python3-pip \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
CMD ["/bin/bash"]
EOF
```

**Add GitHub Actions workflow:**
```yaml
# .github/workflows/publish-kali.yml
name: Publish oasis-kali Image

on:
  push:
    branches: [main]
    paths: ['Dockerfile', '.github/workflows/publish-kali.yml']
  workflow_dispatch:

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ghcr.io/kryptsec/oasis-kali

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          context: .
          push: true
          platforms: linux/amd64
          tags: ${{ env.IMAGE_NAME }}:latest
          labels: |
            org.opencontainers.image.source=https://github.com/KryptSec/oasis-kali
            org.opencontainers.image.description=Kali Linux agent for OASIS benchmarking
```

**Verify:**
```bash
docker pull ghcr.io/kryptsec/oasis-kali:latest
```

---

### Step 5: Make GHCR Packages Public

**For each package:**
```bash
# Via GitHub UI
# Packages → <package-name> → Package settings → Change visibility → Public
```

**Packages to make public:**
- ghcr.io/kryptsec/oasis-kali
- ghcr.io/kryptsec/error-based-disclosure
- ghcr.io/kryptsec/gatekeeper
- ghcr.io/kryptsec/idor-access-control
- ghcr.io/kryptsec/insecure-deserialization
- ghcr.io/kryptsec/jwt-forgery
- ghcr.io/kryptsec/log-disclosure
- ghcr.io/kryptsec/mass-assignment
- ghcr.io/kryptsec/nosql-injection
- ghcr.io/kryptsec/proxy-auth-bypass
- ghcr.io/kryptsec/sqli-auth-bypass
- ghcr.io/kryptsec/sqli-union-session-leak
- ghcr.io/kryptsec/ssrf-internal
- ghcr.io/kryptsec/supply-chain-plugin
- ghcr.io/kryptsec/weak-crypto-hash
- ghcr.io/kryptsec/xxe-injection

**Verify:**
```bash
# Should work without docker login
docker pull ghcr.io/kryptsec/proxy-auth-bypass:latest
```

---

### Step 6: Test End-to-End

**In OASIS repo (with PR #22 branch):**
```bash
cd /path/to/oasis
git checkout feat/challenge-registry-docker

# Should fetch from registry and run
npm run build
./bin/oasis.js run -c proxy-auth-bypass --provider anthropic

# Verify it:
# ✅ Fetches index.json from GitHub
# ✅ Pulls ghcr.io/kryptsec/proxy-auth-bypass:latest
# ✅ Pulls ghcr.io/kryptsec/oasis-kali:latest
# ✅ Starts containers on oasis-net
# ✅ Runs benchmark successfully
```

---

## 🔍 Verification Checklist

Before merging PR #22, confirm:

- [ ] **Repo is public**
  `curl https://github.com/KryptSec/oasis-challenges` (no auth required)

- [ ] **index.json accessible**
  `curl https://raw.githubusercontent.com/KryptSec/oasis-challenges/main/index.json` (returns valid JSON)

- [ ] **Challenge images on GHCR**
  `docker pull ghcr.io/kryptsec/proxy-auth-bypass:latest` (succeeds without login)

- [ ] **oasis-kali image on GHCR**
  `docker pull ghcr.io/kryptsec/oasis-kali:latest` (succeeds without login)

- [ ] **All packages public**
  Visit https://github.com/orgs/KryptSec/packages and verify visibility = Public

- [ ] **End-to-end test passes**
  `oasis run -c proxy-auth-bypass` fetches and runs successfully

---

## 📝 Notes

- **First publish may take 10-15 minutes** (15 images + kali image)
- **GHCR packages inherit repo visibility** by default (private if repo is private)
- **Auto-generate workflow** will keep index.json up-to-date on every challenge.json change
- **Images are tagged with `latest` and commit SHA** for versioning

---

## 🆘 Troubleshooting

**Problem:** GHCR pull fails with 401/403
- **Solution:** Make GHCR packages public (they default to private)

**Problem:** index.json returns 404
- **Solution:** Make repo public OR generate index.json and commit it

**Problem:** Workflows not running
- **Solution:** Check Actions tab, enable workflows, trigger manually

**Problem:** Images not building
- **Solution:** Check Actions logs for build errors, verify Dockerfiles are valid

---

## 🔗 Related

- PR #22: https://github.com/KryptSec/oasis/pull/22
- OASIS docs: https://github.com/KryptSec/oasis#readme
