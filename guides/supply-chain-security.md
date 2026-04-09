# Software Supply Chain Security

A practical guide to securing your software supply chain -- from dependencies to build artifacts to deployment.

---

## Table of Contents

1. [Software Bills of Materials (SBOMs)](#software-bills-of-materials-sboms)
2. [SLSA Build Provenance](#slsa-build-provenance)
3. [Dependency Scanning](#dependency-scanning)
4. [Artifact Signing with Sigstore/Cosign](#artifact-signing-with-sigstorecosign)
5. [Defending Against Typosquatting and Dependency Confusion](#defending-against-typosquatting-and-dependency-confusion)
6. [Lock Files and Pinning Strategies](#lock-files-and-pinning-strategies)

---

## Software Bills of Materials (SBOMs)

An SBOM is a structured inventory of every component in your software. Think of it as the ingredient list for your code. Two dominant formats exist: CycloneDX and SPDX.

### Why SBOMs Matter

When a vulnerability drops (like Log4Shell), the first question is: "Are we affected?" Without an SBOM, you are guessing. With one, you search a file.

### Generating SBOMs

#### CycloneDX

CycloneDX is the more developer-friendly format. It supports applications, containers, firmware, and more.

**Node.js / npm:**

```bash
# Install the CycloneDX npm plugin
npm install --save-dev @cyclonedx/cyclonedx-npm

# Generate SBOM from your project
npx @cyclonedx/cyclonedx-npm --output-file sbom.json --output-format json
```

**Python / pip:**

```bash
pip install cyclonedx-bom

# Generate from a requirements file
cyclonedx-py requirements -i requirements.txt -o sbom.json --format json

# Generate from the current virtualenv
cyclonedx-py environment -o sbom.json --format json
```

**Go:**

```bash
# Install cyclonedx-gomod
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest

# Generate SBOM
cyclonedx-gomod mod -json -output sbom.json
```

**Docker / Container Images:**

```bash
# Syft generates CycloneDX SBOMs from container images
# Install: https://github.com/anchore/syft
syft packages myimage:latest -o cyclonedx-json > sbom.json
```

#### SPDX

SPDX is the ISO/IEC standard (ISO/IEC 5962:2021). It is more widely recognized in compliance contexts.

```bash
# Using Syft (supports both formats)
syft packages myimage:latest -o spdx-json > sbom.spdx.json

# Using Microsoft's SBOM tool
# Install: https://github.com/microsoft/sbom-tool
sbom-tool generate -b ./build -bc . -pn myproject -pv 1.0.0 -ps myorg -nsb https://myorg.com
```

### Consuming SBOMs

Once you have an SBOM, you can scan it for known vulnerabilities without needing the original source code:

```bash
# Scan an SBOM with Grype
grype sbom:./sbom.json

# Scan with Trivy
trivy sbom sbom.json

# Search for a specific package in your SBOM
cat sbom.json | jq '.components[] | select(.name == "lodash")'
```

### Storing and Distributing SBOMs

- Attach SBOMs to container images using ORAS or Cosign
- Store them alongside release artifacts in your CI/CD pipeline
- Include them in your artifact registry (GitHub Releases, Artifactory, etc.)

```bash
# Attach an SBOM to a container image with Cosign
cosign attach sbom --sbom sbom.json myregistry.io/myimage:latest
```

---

## SLSA Build Provenance

SLSA (Supply-chain Levels for Software Artifacts, pronounced "salsa") is a framework for ensuring the integrity of build artifacts. It answers: "Who built this, from what source, using what process?"

### SLSA Levels

| Level | What It Means |
|-------|--------------|
| SLSA 1 | Build process is documented. Provenance exists. |
| SLSA 2 | Build service generates provenance automatically. Provenance is signed. |
| SLSA 3 | Build runs on a hardened, isolated platform. Source is version-controlled. |
| SLSA 4 | Two-party review. Hermetic, reproducible builds. |

### Generating SLSA Provenance with GitHub Actions

The SLSA framework provides official GitHub Actions generators:

```yaml
# .github/workflows/slsa-build.yml
name: SLSA Build
on:
  push:
    tags:
      - 'v*'

permissions:
  id-token: write   # Needed for OIDC
  contents: write   # Needed for uploading release assets
  actions: read      # Needed for reading workflow info

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      hashes: ${{ steps.hash.outputs.hashes }}
    steps:
      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7

      - name: Build artifact
        run: |
          # Your build commands here
          npm ci
          npm run build
          tar -czf myapp-${{ github.ref_name }}.tar.gz dist/

      - name: Generate hashes
        id: hash
        run: |
          # sha256sum generates "hash  filename" pairs
          echo "hashes=$(sha256sum myapp-*.tar.gz | base64 -w0)" >> "$GITHUB_OUTPUT"

      - name: Upload artifact
        uses: actions/upload-artifact@65462800fd760344b1a7b4382951275a0abb4808 # v4.3.3
        with:
          name: myapp
          path: myapp-*.tar.gz

  provenance:
    needs: build
    permissions:
      id-token: write
      contents: write
      actions: read
    # Use the official SLSA generator
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
    with:
      base64-subjects: "${{ needs.build.outputs.hashes }}"
      upload-assets: true
```

### Verifying SLSA Provenance

```bash
# Install slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Verify a downloaded artifact
slsa-verifier verify-artifact myapp-v1.0.0.tar.gz \
  --provenance-path myapp-v1.0.0.tar.gz.intoto.jsonl \
  --source-uri github.com/myorg/myrepo \
  --source-tag v1.0.0
```

---

## Dependency Scanning

Dependency scanners look at your project's dependencies and check them against vulnerability databases (NVD, GitHub Advisory Database, OSV).

### Trivy

Trivy is a broad scanner: containers, filesystems, git repos, Kubernetes, IaC, and more.

```bash
# Install Trivy
# macOS
brew install trivy

# Linux
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Scan a project directory
trivy fs .

# Scan and only show HIGH and CRITICAL
trivy fs --severity HIGH,CRITICAL .

# Scan a container image
trivy image myregistry.io/myimage:latest

# Scan a specific lock file
trivy fs --scanners vuln package-lock.json

# Output as JSON for automation
trivy fs --format json --output results.json .

# Scan and fail if CRITICAL vulns found (good for CI)
trivy fs --severity CRITICAL --exit-code 1 .
```

### Grype

Grype is Anchore's vulnerability scanner. It is fast and focused purely on vulnerability matching.

```bash
# Install Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Scan a directory
grype dir:.

# Scan a container image
grype myregistry.io/myimage:latest

# Scan from an SBOM (no source needed)
grype sbom:./sbom.json

# Only show fixable vulnerabilities
grype dir:. --only-fixed

# Output as JSON
grype dir:. -o json > results.json

# Fail on high severity (for CI)
grype dir:. --fail-on high
```

### OSV-Scanner

OSV-Scanner is Google's open-source vulnerability scanner backed by the OSV database.

```bash
# Install
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Scan a directory (auto-detects lock files)
osv-scanner -r .

# Scan specific files
osv-scanner --lockfile=package-lock.json
osv-scanner --lockfile=requirements.txt
osv-scanner --lockfile=go.sum

# Output as JSON
osv-scanner -r . --format json > results.json

# Scan and compare against an ignore list
osv-scanner -r . --config=osv-scanner.toml
```

**osv-scanner.toml** (for suppressing known false positives):

```toml
[[IgnoredVulns]]
id = "GHSA-xxxx-yyyy-zzzz"
reason = "Not exploitable in our usage. Reviewed 2025-12-01."
```

### Which Scanner to Use

| Tool | Best For | Speed | Database |
|------|---------|-------|----------|
| Trivy | All-in-one scanning (vulns + misconfig + secrets) | Fast | Multiple (NVD, GitHub, etc.) |
| Grype | Pure vulnerability matching, SBOM-based workflows | Very fast | Anchore feed |
| OSV-Scanner | Google ecosystem, broad OSV database coverage | Fast | OSV |

Use at least two. They pull from different databases and have different matching logic. A vulnerability one tool misses, another might catch.

---

## Artifact Signing with Sigstore/Cosign

Sigstore provides "keyless" signing for software artifacts. Instead of managing long-lived GPG keys, you prove your identity through OIDC (e.g., your GitHub Actions identity or your Google account) and get a short-lived certificate from Sigstore's Fulcio CA. The signature is recorded in a tamper-proof transparency log (Rekor).

### Install Cosign

```bash
# macOS
brew install cosign

# Linux
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Or download binary
curl -sSfL https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 -o /usr/local/bin/cosign
chmod +x /usr/local/bin/cosign
```

### Sign a Container Image (Keyless)

```bash
# Sign using OIDC identity (opens browser for auth)
cosign sign myregistry.io/myimage@sha256:abc123...

# In CI (GitHub Actions), OIDC happens automatically
# No browser needed. The workflow identity is the signer.
cosign sign myregistry.io/myimage@sha256:abc123...
```

### Verify a Signed Image

```bash
# Verify that a specific identity signed the image
cosign verify myregistry.io/myimage@sha256:abc123... \
  --certificate-identity "https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

### Sign a Binary/File (Keyless with Blob Signing)

```bash
# Sign a file
cosign sign-blob --output-signature myapp.sig --output-certificate myapp.crt myapp.tar.gz

# Verify a signed file
cosign verify-blob myapp.tar.gz \
  --signature myapp.sig \
  --certificate myapp.crt \
  --certificate-identity "you@example.com" \
  --certificate-oidc-issuer "https://accounts.google.com"
```

### Sign with a Local Key (when keyless is not an option)

```bash
# Generate a key pair
cosign generate-key-pair

# Sign
cosign sign --key cosign.key myregistry.io/myimage@sha256:abc123...

# Verify
cosign verify --key cosign.pub myregistry.io/myimage@sha256:abc123...
```

### GitHub Actions Workflow for Signing

```yaml
jobs:
  sign:
    runs-on: ubuntu-latest
    permissions:
      id-token: write    # Required for OIDC/keyless signing
      packages: write    # Required for pushing to GHCR
    steps:
      - uses: sigstore/cosign-installer@dc72c7d5c4d10cd6bcb8cf6e3fd1d5c67a7e1018 # v3.5.0

      - name: Sign the container image
        run: cosign sign ${{ env.REGISTRY }}/${{ env.IMAGE }}@${{ steps.build.outputs.digest }}
        env:
          COSIGN_EXPERIMENTAL: "true"
```

---

## Defending Against Typosquatting and Dependency Confusion

### Typosquatting

Attackers publish malicious packages with names similar to popular ones. `colorsjs` instead of `colors`, `python-dateutils` instead of `python-dateutil`.

**Defenses:**

1. **Verify package names before installing.** Check the official docs, not just your memory.

2. **Use lock files.** Once a correct package is resolved, the lock file pins it. New typos cannot sneak in without a lock file change.

3. **Audit new dependencies.**
   ```bash
   # npm: review what changed
   npm audit

   # pip: check package metadata before installing
   pip show python-dateutil
   pip index versions python-dateutil

   # Go: verify checksums
   go mod verify
   ```

4. **Use allow-lists in CI.** Tools like Socket.dev or npm's `--ignore-scripts` flag prevent install-time code execution from new packages:
   ```bash
   npm install --ignore-scripts
   npm rebuild  # Run scripts only after review
   ```

### Dependency Confusion

Dependency confusion exploits the way package managers resolve internal vs. public packages. If your company uses a private package called `mycompany-utils` and an attacker publishes `mycompany-utils` on the public npm registry with a higher version number, your build system might pull the attacker's version.

**Defenses:**

1. **Scope your private packages.**
   ```bash
   # npm: use a scope
   # Your private package becomes @mycompany/utils, not mycompany-utils
   npm init --scope=@mycompany
   ```

2. **Configure registry mapping.**
   ```ini
   # .npmrc - route scoped packages to your private registry
   @mycompany:registry=https://npm.mycompany.com/
   ```

3. **Pin the source in pip.**
   ```ini
   # pip.conf
   [global]
   index-url = https://pypi.mycompany.com/simple/
   extra-index-url = https://pypi.org/simple/
   ```
   Warning: pip checks all indexes and picks the highest version. Use `--index-url` alone (no extra) for private packages, or use a repository manager (Artifactory, Nexus) that proxies public and merges with private.

4. **Reserve your internal package names on public registries.** Publish placeholder packages with the same name on npm/PyPI so attackers cannot claim them.

5. **Use repository firewalls.** Tools like Artifactory, Nexus, or Cloudsmith can act as a proxy that blocks unknown public packages from entering your build.

---

## Lock Files and Pinning Strategies

Lock files ensure reproducible builds. Without them, `npm install` today and `npm install` tomorrow might pull different versions.

### Lock File Basics by Ecosystem

| Ecosystem | Lock File | Command to Generate |
|-----------|-----------|-------------------|
| npm | `package-lock.json` | `npm install` (auto-generated) |
| Yarn | `yarn.lock` | `yarn install` |
| pnpm | `pnpm-lock.yaml` | `pnpm install` |
| pip | `requirements.txt` (pinned) | `pip freeze > requirements.txt` |
| pip (modern) | lock via `pip-tools` | `pip-compile requirements.in` |
| Go | `go.sum` | `go mod tidy` |
| Cargo (Rust) | `Cargo.lock` | `cargo build` |

### Rules

1. **Always commit lock files to version control.** This is non-negotiable for applications. Libraries have different conventions (npm recommends not committing `package-lock.json` for libraries).

2. **Use `ci` commands in CI/CD, not `install`.**
   ```bash
   # npm: installs exactly what is in the lock file. Fails if lock is out of date.
   npm ci

   # pip: install exact pinned versions
   pip install -r requirements.txt --require-hashes

   # Go: verify checksums match
   go mod verify
   ```

3. **Pin by hash when possible.**
   ```bash
   # pip-compile can generate hashes
   pip-compile --generate-hashes requirements.in

   # Output looks like:
   # requests==2.31.0 \
   #     --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003eb
   ```

4. **Pin GitHub Actions by commit SHA, not tag.**
   ```yaml
   # Bad: tags can be moved
   - uses: actions/checkout@v4

   # Good: commit SHA is immutable
   - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7
   ```

5. **Use Renovate or Dependabot to keep pins current.** Pinning without updating is a recipe for unpatched vulnerabilities. Automate the update process:
   ```yaml
   # .github/dependabot.yml
   version: 2
   updates:
     - package-ecosystem: "npm"
       directory: "/"
       schedule:
         interval: "weekly"
       open-pull-requests-limit: 10

     - package-ecosystem: "github-actions"
       directory: "/"
       schedule:
         interval: "weekly"
   ```

### Docker Image Pinning

```dockerfile
# Bad: latest can change at any time
FROM node:latest

# Better: pin the tag
FROM node:20.11.1-bookworm-slim

# Best: pin by digest (immutable)
FROM node@sha256:abc123def456...

# Find the digest
docker inspect --format='{{index .RepoDigests 0}}' node:20.11.1-bookworm-slim
```

---

## Quick Reference: Supply Chain Security Checklist

- [ ] Generate SBOMs for every release (CycloneDX or SPDX)
- [ ] Run at least two dependency scanners in CI (Trivy + Grype or OSV-Scanner)
- [ ] Sign all container images and release artifacts with Cosign
- [ ] Generate SLSA provenance for builds
- [ ] Commit lock files and use `npm ci` / equivalent in CI
- [ ] Pin GitHub Actions by SHA
- [ ] Pin Docker base images by digest
- [ ] Scope private packages to prevent dependency confusion
- [ ] Automate dependency updates with Renovate or Dependabot
- [ ] Review new dependencies before adding them
- [ ] Fail CI on CRITICAL/HIGH vulnerabilities

---

*From [AllSecurityNews.com](https://allsecuritynews.com)*
