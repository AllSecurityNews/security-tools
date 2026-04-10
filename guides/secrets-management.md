# Secrets Management: A Practical Guide for Security Engineers

Secrets are the keys to your kingdom. API keys, database passwords, TLS certificates, SSH keys, service account tokens. Every one of them is a potential breach waiting to happen if stored, transmitted, or rotated incorrectly.

This guide covers the full lifecycle of secrets management: storage, rotation, scanning, non-human identity governance, and incident response. Every command is copy-paste ready.

---

## 1. Why Secrets Management Matters

Leaked secrets are one of the most common root causes of cloud breaches. The numbers paint a clear picture:

- GitHub reports finding over 10 million secrets in public repositories in a single year.
- Over 80% of data breaches involve compromised credentials (Verizon DBIR, 2024).
- The average cost of a breach caused by stolen credentials exceeds $4.5 million (IBM).
- Attackers actively scan GitHub, GitLab, and Bitbucket for freshly committed secrets. Automated bots can exploit a leaked AWS key within minutes of it hitting a public repo.

Hard-coded secrets in source code, environment variables written to logs, credentials shared in Slack channels, API keys stored in plaintext config files. These are not edge cases. They are the norm in organizations without a secrets management strategy.

The fix is not complicated, but it requires discipline: centralize secret storage, automate rotation, scan for leaks, and treat every credential as something that will eventually be compromised.

---

## 2. Types of Secrets

Not all secrets are the same. Each type has different storage requirements, rotation frequencies, and risk profiles.

| Secret Type | Examples | Typical Rotation | Risk if Leaked |
|---|---|---|---|
| API Keys | Stripe keys, SendGrid tokens, cloud provider keys | 90 days | Direct service access, financial loss |
| Database Credentials | MySQL/Postgres usernames and passwords | 30-90 days | Full data access, exfiltration |
| TLS/SSL Certificates | Server certs, client certs, CA certs | Annual (automate with ACME) | Man-in-the-middle attacks |
| SSH Keys | User keys, deploy keys, host keys | Annual or on personnel change | Server access, lateral movement |
| OAuth/JWT Tokens | Access tokens, refresh tokens, service tokens | Hours to days | Account takeover, API abuse |
| Encryption Keys | AES keys, KMS keys, PGP keys | Annual or per policy | Data decryption, integrity loss |
| Service Account Credentials | Cloud IAM keys, Kubernetes service accounts | 90 days | Privilege escalation |

---

## 3. Secret Storage Solutions

### 3.1 HashiCorp Vault

Vault is the most widely adopted dedicated secrets management platform. It supports dynamic secrets, encryption as a service, and fine-grained access control.

#### Installation and Setup

```bash
# Install Vault (Linux)
curl -fsSL https://releases.hashicorp.com/vault/1.17.0/vault_1.17.0_linux_amd64.zip -o vault.zip
unzip vault.zip
sudo mv vault /usr/local/bin/
vault --version

# Start a dev server (NOT for production)
vault server -dev

# In another terminal, set the address and token
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='hvs.your-dev-root-token'
```

#### Production Configuration

```hcl
# /etc/vault.d/vault.hcl
storage "raft" {
  path    = "/opt/vault/data"
  node_id = "vault-node-1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_cert_file = "/opt/vault/tls/vault-cert.pem"
  tls_key_file  = "/opt/vault/tls/vault-key.pem"
}

api_addr = "https://vault.example.com:8200"
cluster_addr = "https://vault.example.com:8201"

ui = true
```

```bash
# Initialize Vault (production)
vault operator init -key-shares=5 -key-threshold=3

# Unseal with 3 of 5 keys
vault operator unseal <key-1>
vault operator unseal <key-2>
vault operator unseal <key-3>

# Check status
vault status
```

#### Basic Secret Operations

```bash
# Enable the KV v2 secrets engine
vault secrets enable -path=secret kv-v2

# Store a secret
vault kv put secret/myapp/database \
  username="dbadmin" \
  password="s3cure-p@ssw0rd" \
  host="db.example.com" \
  port="5432"

# Read a secret
vault kv get secret/myapp/database

# Read a specific field
vault kv get -field=password secret/myapp/database

# Read as JSON (useful for scripting)
vault kv get -format=json secret/myapp/database | jq -r '.data.data.password'

# List secrets at a path
vault kv list secret/myapp/

# Delete a secret
vault kv delete secret/myapp/database

# Undelete (soft delete recovery)
vault kv undelete -versions=1 secret/myapp/database
```

#### Dynamic Secrets (Database Example)

Dynamic secrets are generated on demand and automatically revoked after a TTL. This eliminates standing credentials entirely.

```bash
# Enable the database secrets engine
vault secrets enable database

# Configure a PostgreSQL connection
vault write database/config/mydb \
  plugin_name=postgresql-database-plugin \
  allowed_roles="readonly","readwrite" \
  connection_url="postgresql://{{username}}:{{password}}@db.example.com:5432/myapp?sslmode=require" \
  username="vault_admin" \
  password="vault_admin_password"

# Create a read-only role with a 1-hour TTL
vault write database/roles/readonly \
  db_name=mydb \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="24h"

# Generate temporary credentials
vault read database/creds/readonly
# Returns: username=v-token-readonly-abc123, password=generated-password, lease_duration=1h
```

#### Transit Engine (Encryption as a Service)

The transit engine lets applications encrypt and decrypt data without ever handling raw encryption keys.

```bash
# Enable transit engine
vault secrets enable transit

# Create an encryption key
vault write -f transit/keys/payment-data

# Encrypt data (input must be base64 encoded)
vault write transit/encrypt/payment-data \
  plaintext=$(echo -n "4111-1111-1111-1111" | base64)

# Returns: ciphertext=vault:v1:abc123...

# Decrypt data
vault write transit/decrypt/payment-data \
  ciphertext="vault:v1:abc123..."

# Decode the base64 result
echo "decoded-base64-output" | base64 --decode

# Rotate the encryption key (re-encryption uses the new key version)
vault write -f transit/keys/payment-data/rotate
```

#### Vault Policies

```hcl
# policy-readonly.hcl
path "secret/data/myapp/*" {
  capabilities = ["read", "list"]
}

path "database/creds/readonly" {
  capabilities = ["read"]
}
```

```bash
# Write the policy
vault policy write app-readonly policy-readonly.hcl

# Create a token with this policy
vault token create -policy=app-readonly -ttl=8h
```

---

### 3.2 AWS Secrets Manager

AWS Secrets Manager provides managed secret storage with built-in rotation for RDS, Redshift, and DocumentDB.

```bash
# Create a secret
aws secretsmanager create-secret \
  --name "prod/myapp/database" \
  --description "Production database credentials" \
  --secret-string '{"username":"dbadmin","password":"s3cure-p@ss","host":"mydb.cluster-abc.us-east-1.rds.amazonaws.com","port":"5432","dbname":"myapp"}'

# Retrieve a secret
aws secretsmanager get-secret-value \
  --secret-id "prod/myapp/database" \
  --query 'SecretString' \
  --output text | jq .

# Retrieve a specific version
aws secretsmanager get-secret-value \
  --secret-id "prod/myapp/database" \
  --version-stage AWSPREVIOUS

# Update a secret
aws secretsmanager update-secret \
  --secret-id "prod/myapp/database" \
  --secret-string '{"username":"dbadmin","password":"new-p@ssw0rd","host":"mydb.cluster-abc.us-east-1.rds.amazonaws.com","port":"5432","dbname":"myapp"}'

# Enable automatic rotation (Lambda function required)
aws secretsmanager rotate-secret \
  --secret-id "prod/myapp/database" \
  --rotation-lambda-arn "arn:aws:lambda:us-east-1:123456789012:function:SecretsManagerRotation" \
  --rotation-rules '{"AutomaticallyAfterDays": 30}'

# Trigger immediate rotation
aws secretsmanager rotate-secret \
  --secret-id "prod/myapp/database"

# List all secrets
aws secretsmanager list-secrets --query 'SecretList[].Name' --output table

# Delete a secret (with recovery window)
aws secretsmanager delete-secret \
  --secret-id "prod/myapp/database" \
  --recovery-window-in-days 7

# Restore a deleted secret within the recovery window
aws secretsmanager restore-secret \
  --secret-id "prod/myapp/database"
```

#### Using Secrets in Application Code (Python)

```python
import json
import boto3
from botocore.exceptions import ClientError

def get_secret(secret_name, region="us-east-1"):
    client = boto3.client("secretsmanager", region_name=region)
    try:
        response = client.get_secret_value(SecretId=secret_name)
        return json.loads(response["SecretString"])
    except ClientError as e:
        raise e

# Usage
creds = get_secret("prod/myapp/database")
db_url = f"postgresql://{creds['username']}:{creds['password']}@{creds['host']}:{creds['port']}/{creds['dbname']}"
```

---

### 3.3 Azure Key Vault

```bash
# Create a Key Vault
az keyvault create \
  --name "myapp-prod-kv" \
  --resource-group "myapp-rg" \
  --location "eastus" \
  --sku standard

# Store a secret
az keyvault secret set \
  --vault-name "myapp-prod-kv" \
  --name "database-password" \
  --value "s3cure-p@ssw0rd"

# Retrieve a secret
az keyvault secret show \
  --vault-name "myapp-prod-kv" \
  --name "database-password" \
  --query "value" \
  --output tsv

# List all secrets
az keyvault secret list \
  --vault-name "myapp-prod-kv" \
  --query "[].name" \
  --output table

# Set an expiration date on a secret
az keyvault secret set-attributes \
  --vault-name "myapp-prod-kv" \
  --name "database-password" \
  --expires "2025-12-31T23:59:59Z"

# Delete a secret (soft delete)
az keyvault secret delete \
  --vault-name "myapp-prod-kv" \
  --name "database-password"

# Recover a soft-deleted secret
az keyvault secret recover \
  --vault-name "myapp-prod-kv" \
  --name "database-password"

# Store a certificate
az keyvault certificate import \
  --vault-name "myapp-prod-kv" \
  --name "myapp-tls" \
  --file "./myapp-cert.pfx" \
  --password "pfx-password"

# Grant access to a managed identity
az keyvault set-policy \
  --name "myapp-prod-kv" \
  --object-id "<managed-identity-object-id>" \
  --secret-permissions get list
```

---

### 3.4 GCP Secret Manager

```bash
# Enable the Secret Manager API
gcloud services enable secretmanager.googleapis.com

# Create a secret
echo -n "s3cure-p@ssw0rd" | gcloud secrets create database-password \
  --data-file=- \
  --replication-policy="automatic" \
  --labels="env=prod,app=myapp"

# Add a new version of a secret
echo -n "new-p@ssw0rd" | gcloud secrets versions add database-password --data-file=-

# Access the latest version
gcloud secrets versions access latest --secret=database-password

# Access a specific version
gcloud secrets versions access 2 --secret=database-password

# List all secrets
gcloud secrets list --format="table(name, createTime, replication.automatic)"

# List versions of a secret
gcloud secrets versions list database-password

# Disable an old version
gcloud secrets versions disable 1 --secret=database-password

# Destroy a version permanently
gcloud secrets versions destroy 1 --secret=database-password

# Set an expiration on a secret
gcloud secrets update database-password \
  --expire-time="2025-12-31T23:59:59Z"

# Grant access to a service account
gcloud secrets add-iam-policy-binding database-password \
  --member="serviceAccount:myapp@myproject.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Delete a secret entirely
gcloud secrets delete database-password
```

---

## 4. Kubernetes Secrets Best Practices

### Why Base64 Encoding Is NOT Encryption

This is one of the most common misconceptions in Kubernetes security. Kubernetes Secrets are stored as base64-encoded strings by default. Base64 is an encoding scheme, not encryption. Anyone with access to the cluster or etcd can decode them instantly.

```bash
# Create a Kubernetes secret
kubectl create secret generic db-creds \
  --from-literal=username=dbadmin \
  --from-literal=password=s3cure-p@ss

# View the secret (base64 encoded, NOT encrypted)
kubectl get secret db-creds -o yaml
# data:
#   username: ZGJhZG1pbg==
#   password: czNjdXJlLXBAc3M=

# Decode it trivially
echo "czNjdXJlLXBAc3M=" | base64 --decode
# Output: s3cure-p@ss
```

To actually protect secrets in Kubernetes, you need one of these:

1. **Enable etcd encryption at rest** (encrypts secrets in the backing store)
2. **Use an external secrets manager** (Vault, AWS Secrets Manager, etc.)
3. **Use Sealed Secrets** (encrypts before it ever reaches the cluster)

#### Enable etcd Encryption at Rest

```yaml
# /etc/kubernetes/encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-32-byte-key>
      - identity: {}
```

```bash
# Generate a 32-byte key
head -c 32 /dev/urandom | base64

# Pass the encryption config to the API server
# Add this flag to kube-apiserver:
# --encryption-provider-config=/etc/kubernetes/encryption-config.yaml

# Re-encrypt all existing secrets
kubectl get secrets --all-namespaces -o json | kubectl replace -f -
```

---

### External Secrets Operator

The External Secrets Operator (ESO) syncs secrets from external providers (Vault, AWS, Azure, GCP) into Kubernetes Secrets automatically.

```bash
# Install via Helm
helm repo add external-secrets https://charts.external-secrets.io
helm repo update

helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets \
  --create-namespace \
  --set installCRDs=true
```

#### Configure a SecretStore (AWS Secrets Manager example)

```yaml
# aws-secret-store.yaml
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: aws-secrets
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        jwt:
          serviceAccountRef:
            name: external-secrets-sa
            namespace: external-secrets
```

#### Create an ExternalSecret

```yaml
# db-external-secret.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-creds
  namespace: myapp
spec:
  refreshInterval: 5m
  secretStoreRef:
    name: aws-secrets
    kind: ClusterSecretStore
  target:
    name: db-creds
    creationPolicy: Owner
  data:
    - secretKey: username
      remoteRef:
        key: prod/myapp/database
        property: username
    - secretKey: password
      remoteRef:
        key: prod/myapp/database
        property: password
```

```bash
kubectl apply -f aws-secret-store.yaml
kubectl apply -f db-external-secret.yaml

# Verify the secret was created
kubectl get externalsecret db-creds -n myapp
kubectl get secret db-creds -n myapp -o yaml
```

---

### Sealed Secrets

Sealed Secrets let you encrypt secrets client-side so that only the cluster can decrypt them. You can safely commit SealedSecret manifests to Git.

```bash
# Install the controller in the cluster
helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets
helm install sealed-secrets sealed-secrets/sealed-secrets \
  --namespace kube-system

# Install kubeseal CLI (macOS)
brew install kubeseal

# Install kubeseal CLI (Linux)
KUBESEAL_VERSION="0.27.0"
curl -OL "https://github.com/bitnami-labs/sealed-secrets/releases/download/v${KUBESEAL_VERSION}/kubeseal-${KUBESEAL_VERSION}-linux-amd64.tar.gz"
tar -xvzf kubeseal-${KUBESEAL_VERSION}-linux-amd64.tar.gz kubeseal
sudo install -m 755 kubeseal /usr/local/bin/kubeseal

# Create a regular secret manifest (do NOT apply it)
kubectl create secret generic db-creds \
  --from-literal=username=dbadmin \
  --from-literal=password=s3cure-p@ss \
  --dry-run=client -o yaml > db-creds-secret.yaml

# Seal it
kubeseal --format=yaml < db-creds-secret.yaml > db-creds-sealed.yaml

# Remove the plaintext version
rm db-creds-secret.yaml

# Apply the sealed secret (safe to commit to git)
kubectl apply -f db-creds-sealed.yaml

# The controller decrypts it and creates a regular Secret in-cluster
kubectl get secret db-creds -o yaml
```

---

## 5. Secret Rotation Patterns

### Zero-Downtime Rotation Strategy

The key principle: never have a moment where the old secret is revoked but the new one is not yet deployed. Follow the "dual-write" pattern:

1. **Generate the new secret** in your secrets manager.
2. **Update the target system** to accept BOTH the old and new secret.
3. **Deploy the new secret** to all consumers.
4. **Verify all consumers** are using the new secret.
5. **Revoke the old secret** only after full rollout confirmation.

### Automated Rotation with AWS Secrets Manager

```python
# Lambda rotation function skeleton for AWS Secrets Manager
import boto3
import json
import string
import secrets

def lambda_handler(event, context):
    secret_id = event["SecretId"]
    step = event["Step"]
    token = event["ClientRequestToken"]

    client = boto3.client("secretsmanager")

    if step == "createSecret":
        # Generate a new password
        new_password = ''.join(
            secrets.choice(string.ascii_letters + string.digits + "!@#$%")
            for _ in range(32)
        )
        current = json.loads(
            client.get_secret_value(
                SecretId=secret_id, VersionStage="AWSCURRENT"
            )["SecretString"]
        )
        current["password"] = new_password
        client.put_secret_value(
            SecretId=secret_id,
            ClientRequestToken=token,
            SecretString=json.dumps(current),
            VersionStages=["AWSPENDING"],
        )

    elif step == "setSecret":
        # Update the password in the actual database
        pending = json.loads(
            client.get_secret_value(
                SecretId=secret_id,
                VersionId=token,
                VersionStage="AWSPENDING",
            )["SecretString"]
        )
        # Connect to DB and ALTER USER with new password
        update_database_password(pending)

    elif step == "testSecret":
        # Verify the new credentials work
        pending = json.loads(
            client.get_secret_value(
                SecretId=secret_id,
                VersionId=token,
                VersionStage="AWSPENDING",
            )["SecretString"]
        )
        test_database_connection(pending)

    elif step == "finishSecret":
        # Promote AWSPENDING to AWSCURRENT
        client.update_secret_version_stage(
            SecretId=secret_id,
            VersionStage="AWSCURRENT",
            MoveToVersionId=token,
            RemoveFromVersionId=get_current_version(client, secret_id),
        )
```

### Database Credential Rotation

```bash
# PostgreSQL: Create a new password and update the user
NEW_PASS=$(openssl rand -base64 24)

psql -h db.example.com -U admin -d myapp -c \
  "ALTER USER appuser WITH PASSWORD '${NEW_PASS}';"

# Update the secret in Vault
vault kv put secret/myapp/database \
  username="appuser" \
  password="${NEW_PASS}" \
  host="db.example.com"

# Rolling restart of application pods to pick up new credentials
kubectl rollout restart deployment/myapp -n production
```

### API Key Rotation

```bash
# Step 1: Generate a new API key from your provider (example: Stripe)
# New key is created in the Stripe dashboard or via API

# Step 2: Store the new key alongside the old one
vault kv put secret/myapp/stripe \
  api_key_current="sk_live_NEW_KEY" \
  api_key_previous="sk_live_OLD_KEY"

# Step 3: Deploy application update that uses the new key
kubectl set env deployment/myapp \
  STRIPE_API_KEY="sk_live_NEW_KEY" -n production

# Step 4: Monitor for errors, then revoke the old key
# After 24 hours with no errors referencing the old key:
vault kv put secret/myapp/stripe \
  api_key_current="sk_live_NEW_KEY"
```

### Certificate Rotation with Cert-Manager

```yaml
# cert-manager automatically handles TLS certificate rotation
# certificate.yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: myapp-tls
  namespace: production
spec:
  secretName: myapp-tls-secret
  duration: 2160h    # 90 days
  renewBefore: 720h  # Renew 30 days before expiry
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - myapp.example.com
    - api.myapp.example.com
```

---

## 6. Non-Human Identity (NHI) Lifecycle

Non-human identities (NHIs) are the service accounts, bot accounts, CI/CD tokens, and API consumers that vastly outnumber human users in most environments. They are often the most neglected and most privileged identities in an organization.

### Types of NHIs

| NHI Type | Examples | Common Risks |
|---|---|---|
| Service Accounts | Cloud IAM service accounts, Kubernetes service accounts | Over-permissioned, never rotated |
| Bot Accounts | CI/CD bots, monitoring agents, chat integrations | Shared credentials, no MFA |
| API Consumers | Third-party integrations, partner APIs | Long-lived tokens, no expiry |
| Machine Identities | Server certificates, workload identities | Forgotten after decommission |

### Discovery and Inventory

You cannot secure what you cannot see. Start by cataloging every NHI in your environment.

```bash
# AWS: List all IAM users with programmatic access (no console login = likely NHI)
aws iam list-users --query 'Users[?PasswordLastUsed==`null`].[UserName,CreateDate]' --output table

# AWS: Find access keys older than 90 days
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 --decode | \
  awk -F',' '$10 != "N/A" && $10 != "access_key_1_last_rotated" {
    split($10,d,"T");
    if (d[1] < strftime("%Y-%m-%d", systime()-7776000))
      print $1, $10
  }'

# AWS: List all service accounts with attached policies
aws iam list-users --output json | jq -r '.Users[].UserName' | while read user; do
  policies=$(aws iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[].PolicyName' --output text)
  if [ -n "$policies" ]; then
    echo "User: $user | Policies: $policies"
  fi
done

# GCP: List all service accounts across projects
gcloud iam service-accounts list --format="table(email, displayName, disabled)"

# GCP: Find service account keys older than 90 days
gcloud iam service-accounts list --format="value(email)" | while read sa; do
  gcloud iam service-accounts keys list --iam-account="$sa" \
    --format="table(name.basename(), validAfterTime, validBeforeTime, keyType)" \
    --filter="keyType=USER_MANAGED"
done

# Kubernetes: List all service accounts across namespaces
kubectl get serviceaccounts --all-namespaces -o custom-columns=\
NAMESPACE:.metadata.namespace,NAME:.metadata.name,SECRETS:.secrets[*].name

# Azure: List all service principals
az ad sp list --all --query "[].{Name:displayName, AppId:appId, Created:createdDateTime}" --output table
```

### Expiry Policies

Every NHI should have an enforced expiration. No exceptions.

```bash
# AWS: Set a policy requiring key rotation within 90 days
# Use AWS Config rule to detect non-compliance
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "access-keys-rotated",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "ACCESS_KEYS_ROTATED"
  },
  "InputParameters": "{\"maxAccessKeyAge\":\"90\"}"
}'

# GCP: Create a service account key with expiration
gcloud iam service-accounts keys create key.json \
  --iam-account="myapp@myproject.iam.gserviceaccount.com" \
  --key-file-type=json

# Set org policy to limit key lifetime (requires org admin)
gcloud resource-manager org-policies allow \
  --organization=ORGANIZATION_ID \
  constraints/iam.serviceAccountKeyExpiryHours \
  --values=2160  # 90 days in hours
```

### Monitoring NHI Activity

```bash
# AWS: Check when a service account last used its access key
aws iam get-access-key-last-used --access-key-id AKIAEXAMPLE123

# AWS: Find unused service accounts (no activity in 90 days)
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 --decode | \
  csvtool col 1,5,11,16 - | grep -v "password_last_used"

# GCP: Query audit logs for service account activity
gcloud logging read \
  'protoPayload.authenticationInfo.principalEmail:"@myproject.iam.gserviceaccount.com"' \
  --project=myproject \
  --freshness=90d \
  --format="table(timestamp, protoPayload.authenticationInfo.principalEmail, protoPayload.methodName)"
```

### NHI Governance Checklist

- [ ] Maintain a centralized inventory of all non-human identities
- [ ] Assign an owner (human) to every NHI
- [ ] Enforce maximum credential lifetime (90 days recommended)
- [ ] Apply least-privilege principles to all NHI permissions
- [ ] Monitor for unused or dormant NHIs and disable after 90 days of inactivity
- [ ] Require justification for any NHI with admin or write permissions
- [ ] Include NHIs in your incident response playbook
- [ ] Review NHI permissions quarterly

---

## 7. Secret Scanning in CI/CD

### Pre-Commit Hooks with detect-secrets

Catch secrets before they ever reach your repository.

```bash
# Install detect-secrets
pip install detect-secrets

# Generate a baseline (scans current codebase and records known findings)
detect-secrets scan > .secrets.baseline

# Review the baseline and mark false positives
detect-secrets audit .secrets.baseline

# Install the pre-commit hook
pip install pre-commit

# Add to .pre-commit-config.yaml
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.5.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
        exclude: package-lock\.json|\.secrets\.baseline
EOF

# Install the hooks
pre-commit install

# Test it manually
pre-commit run detect-secrets --all-files

# Example: This commit would be blocked
echo 'AWS_SECRET_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"' >> config.py
git add config.py
git commit -m "add config"
# ERROR: Potential secret detected in config.py
```

### GitHub Secret Scanning

GitHub's built-in secret scanning detects committed secrets and alerts you. For GitHub Advanced Security customers, push protection blocks the push entirely.

```bash
# Check if secret scanning is enabled on your repo
gh api repos/{owner}/{repo} --jq '.security_and_analysis.secret_scanning.status'

# List secret scanning alerts
gh api repos/{owner}/{repo}/secret-scanning/alerts --jq '.[] | {number, state, secret_type, created_at}'

# Resolve an alert (after rotation)
gh api repos/{owner}/{repo}/secret-scanning/alerts/{alert_number} \
  -X PATCH \
  -f state="resolved" \
  -f resolution="revoked"
```

Enable push protection via the repository settings:

```
Settings > Code security and analysis > Secret scanning > Push protection > Enable
```

### Gitleaks in CI Pipelines

Gitleaks is a fast, open-source secret scanner that works well in CI/CD.

```bash
# Install gitleaks
brew install gitleaks  # macOS
# Or download the binary
curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz | tar xz

# Scan the current directory
gitleaks detect --source . --verbose

# Scan git history
gitleaks detect --source . --log-opts="--all" --verbose

# Scan only staged changes (good for pre-commit)
gitleaks protect --staged --verbose
```

#### GitHub Actions Integration

```yaml
# .github/workflows/secret-scan.yml
name: Secret Scanning
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

#### GitLab CI Integration

```yaml
# .gitlab-ci.yml
secret_scan:
  stage: test
  image: zricethezav/gitleaks:latest
  script:
    - gitleaks detect --source . --verbose --report-format json --report-path gitleaks-report.json
  artifacts:
    paths:
      - gitleaks-report.json
    when: always
  allow_failure: false
```

#### Custom Gitleaks Configuration

```toml
# .gitleaks.toml
title = "Custom Gitleaks Config"

[allowlist]
description = "Global allowlist"
paths = [
  '''go\.sum''',
  '''package-lock\.json''',
  '''\.secrets\.baseline''',
]

[[rules]]
id = "internal-api-key"
description = "Internal API Key Pattern"
regex = '''INTERNAL_API_KEY\s*=\s*['"]([A-Za-z0-9_\-]{32,})['"]'''
tags = ["api", "internal"]
```

---

## 8. What to Do When a Secret Leaks

A leaked secret is a security incident. Speed matters. Every minute between leak and revocation is a window for attackers.

### Immediate Response Steps (First 15 Minutes)

```
1. REVOKE the leaked secret immediately
   - Do not wait for an investigation
   - Do not wait for a replacement to be ready
   - Revoke first, fix the disruption second

2. ASSESS the scope
   - What type of secret was leaked?
   - What access does it grant?
   - How long was it exposed?
   - Where was it exposed? (public repo, logs, Slack, etc.)

3. GENERATE a new secret
   - Create the replacement credential
   - Store it in your secrets manager

4. DEPLOY the new secret
   - Update all consumers
   - Verify functionality
```

### Rotation Checklist by Secret Type

#### Leaked AWS Access Key

```bash
# 1. Disable the compromised key immediately
aws iam update-access-key \
  --user-name compromised-user \
  --access-key-id AKIACOMPROMISED \
  --status Inactive

# 2. Create a new key
aws iam create-access-key --user-name compromised-user

# 3. Update all services using the old key
# (update your secrets manager, redeploy services)

# 4. Check CloudTrail for unauthorized usage
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIACOMPROMISED \
  --start-time "2024-01-01T00:00:00Z" \
  --query 'Events[].{Time:EventTime,Event:EventName,Source:EventSource}' \
  --output table

# 5. Delete the compromised key after confirming no legitimate use
aws iam delete-access-key \
  --user-name compromised-user \
  --access-key-id AKIACOMPROMISED
```

#### Leaked Database Password

```bash
# 1. Change the password immediately
psql -h db.example.com -U admin -c \
  "ALTER USER appuser WITH PASSWORD '$(openssl rand -base64 24)';"

# 2. Kill all existing connections from the compromised user
psql -h db.example.com -U admin -c \
  "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='appuser';"

# 3. Check for unauthorized queries
psql -h db.example.com -U admin -c \
  "SELECT query, calls, mean_exec_time FROM pg_stat_statements WHERE userid=(SELECT usesysid FROM pg_user WHERE usename='appuser') ORDER BY calls DESC LIMIT 20;"

# 4. Review connection logs for unusual source IPs
grep "appuser" /var/log/postgresql/postgresql-*.log | grep -v "known-ip-range"
```

#### Leaked GitHub Personal Access Token

```bash
# 1. Revoke the token via GitHub API
gh api -X DELETE /applications/{client_id}/token \
  -f access_token="ghp_COMPROMISED_TOKEN"

# Or revoke via the GitHub UI:
# Settings > Developer settings > Personal access tokens > Delete

# 2. Generate a new token with minimal required scopes

# 3. Audit recent activity
gh api /users/{username}/events --jq '.[].type' | sort | uniq -c | sort -rn

# 4. Check for unauthorized repository access
gh api /user/repos --jq '.[].full_name' | while read repo; do
  echo "--- $repo ---"
  gh api "repos/$repo/events" --jq '.[0:3] | .[].type' 2>/dev/null
done
```

### Post-Incident Review

After the immediate response, conduct a post-incident review within 48 hours.

**Questions to answer:**

1. **How was the secret exposed?**
   - Hard-coded in source code?
   - Logged in plaintext?
   - Shared in a message or document?
   - Included in a container image?

2. **Why did existing controls fail?**
   - Was secret scanning enabled?
   - Were pre-commit hooks in place?
   - Was the secret stored in a secrets manager or in a config file?

3. **What was the blast radius?**
   - What systems could the attacker have accessed?
   - Was there evidence of unauthorized access?
   - Was any data exfiltrated?

4. **What changes prevent recurrence?**
   - Implement or improve secret scanning
   - Move secrets to a proper secrets manager
   - Add automated rotation
   - Reduce secret scope and permissions
   - Train the team on secure credential handling

**Incident Documentation Template:**

```markdown
## Secret Leak Incident Report

**Date Detected**: YYYY-MM-DD HH:MM UTC
**Date Resolved**: YYYY-MM-DD HH:MM UTC
**Time to Revocation**: X minutes

**Secret Type**: [API Key / DB Password / Token / Certificate]
**Exposure Location**: [GitHub / Logs / Slack / Other]
**Exposure Duration**: [Estimated time the secret was accessible]

**Impact Assessment**:
- Systems accessible with this credential: [list]
- Evidence of unauthorized access: [yes/no, details]
- Data exposure: [none / potential / confirmed]

**Root Cause**: [How the secret ended up in the exposed location]

**Remediation Actions Taken**:
1. [Revoked credential at HH:MM UTC]
2. [Generated new credential]
3. [Deployed to all consumers]
4. [Audited access logs]

**Preventive Measures**:
1. [Specific changes to prevent recurrence]
2. [Timeline for implementation]

**Lessons Learned**: [Key takeaways for the team]
```

---

## Quick Reference: Secrets Management Maturity Model

| Level | Description | Characteristics |
|---|---|---|
| **1 - Ad Hoc** | No formal process | Secrets in code, env vars, shared docs |
| **2 - Managed** | Basic awareness | Secrets in a vault, some rotation |
| **3 - Defined** | Standardized process | All secrets centralized, scanning in CI, rotation policies |
| **4 - Measured** | Metrics-driven | Rotation compliance tracked, NHI inventory maintained, MTTD/MTTR measured |
| **5 - Optimized** | Continuous improvement | Dynamic secrets everywhere, zero standing credentials, automated response |

Most organizations are at Level 1 or 2. Getting to Level 3 eliminates the majority of credential-related breaches. Levels 4 and 5 are where you move from reactive to proactive security.

---

## Summary

Secrets management is not a tool problem. It is a discipline problem. The tools exist: Vault, cloud-native secret managers, Sealed Secrets, scanning pipelines. The challenge is building the habits and processes to use them consistently.

Start here:

1. **Centralize**: Move every secret into a dedicated secrets manager. Zero exceptions.
2. **Scan**: Add secret scanning to every CI pipeline and every developer workstation.
3. **Rotate**: Automate rotation for every credential. If you cannot automate it, set calendar reminders and track compliance.
4. **Inventory**: Know every non-human identity in your environment. Assign owners. Enforce expiry.
5. **Prepare**: Have a playbook ready for when (not if) a secret leaks. Practice it.

The goal is not perfection. The goal is to make credential compromise survivable through fast detection and fast rotation.

---

From [AllSecurityNews.com](https://allsecuritynews.com)
