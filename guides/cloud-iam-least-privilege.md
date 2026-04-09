# Cloud IAM Least Privilege Guide

Overprivileged cloud identities are the number one root cause of cloud breaches. This guide covers how to find and fix excessive permissions in AWS, Azure, and GCP.

## The Problem

Most cloud environments have:
- Service accounts with admin-level access that only need read permissions
- Users with broad policies attached "temporarily" that were never removed
- Cross-account trust relationships that are wider than necessary
- API keys and service account keys that have not been rotated in months

The fix is not complicated, but it requires systematic analysis.

## AWS

### Find overprivileged IAM users and roles

```bash
# List all IAM users with their attached policies
aws iam list-users --query 'Users[*].[UserName,CreateDate]' --output table

# For each user, check what policies are attached
aws iam list-attached-user-policies --user-name USERNAME

# Find users with AdministratorAccess
aws iam list-entities-for-policy \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --query 'PolicyUsers[*].UserName'

# List all roles with admin access
aws iam list-entities-for-policy \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --query 'PolicyRoles[*].RoleName'
```

### Check for unused credentials

```bash
# Generate a credential report
aws iam generate-credential-report
aws iam get-credential-report --query Content --output text | base64 -d > cred_report.csv

# Key columns to check:
# - password_last_used (unused console access)
# - access_key_1_last_used_date (unused API keys)
# - access_key_2_last_used_date
# - mfa_active (should be true for all console users)
```

### Use Access Analyzer to find unused permissions

```bash
# Enable IAM Access Analyzer (one-time setup)
aws accessanalyzer create-analyzer \
  --analyzer-name account-analyzer \
  --type ACCOUNT

# List findings (external access)
aws accessanalyzer list-findings --analyzer-name account-analyzer

# Generate a policy based on actual usage (last 90 days)
aws accessanalyzer generate-policy \
  --principal-arn arn:aws:iam::123456789012:role/MyRole \
  --cloud-trail-details '{
    "trailArn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail",
    "startTime": "2026-01-01T00:00:00Z",
    "endTime": "2026-04-01T00:00:00Z"
  }'
```

### Implement least privilege policies

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3ReadOnlySpecificBucket",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-app-data",
        "arn:aws:s3:::my-app-data/*"
      ]
    }
  ]
}
```

Key principles:
- Specify exact actions (not `s3:*`)
- Restrict to specific resources (not `*`)
- Use conditions where possible (IP, MFA, time-based)
- Prefer managed policies over inline policies

### Service account key hygiene

```bash
# Find access keys older than 90 days
aws iam list-access-keys --user-name USERNAME --query \
  'AccessKeyMetadata[?CreateDate<=`2026-01-01`].[AccessKeyId,CreateDate,Status]'

# Rotate: create new key, update applications, deactivate old key, then delete
aws iam create-access-key --user-name USERNAME
# Update your application with the new key
aws iam update-access-key --user-name USERNAME --access-key-id OLD_KEY --status Inactive
# After confirming the new key works:
aws iam delete-access-key --user-name USERNAME --access-key-id OLD_KEY
```

## Azure

### Find overprivileged identities

```bash
# List all role assignments at subscription level
az role assignment list --all --query \
  "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor'].\
  {Principal:principalName, Role:roleDefinitionName, Scope:scope}" \
  --output table

# Find service principals with broad permissions
az ad sp list --all --query "[].{Name:displayName, AppId:appId}" --output table

# Check for custom roles with dangerous permissions
az role definition list --custom-role-only \
  --query "[?contains(permissions[0].actions, '*')].\
  {Name:roleName, Actions:permissions[0].actions}" \
  --output table
```

### Use Privileged Identity Management (PIM)

Instead of permanent admin access, use just-in-time elevation:

```bash
# Require PIM activation for sensitive roles
# Configure in Azure AD > Privileged Identity Management > Azure AD roles

# Key settings:
# - Maximum activation duration: 4 hours
# - Require MFA on activation
# - Require approval for Global Admin, Security Admin
# - Configure alerts for unusual activations
```

### Managed Identity instead of service principal keys

```bash
# Create a user-assigned managed identity
az identity create -g myResourceGroup -n myAppIdentity

# Assign it to a VM or App Service
az vm identity assign -g myResourceGroup -n myVM \
  --identities myAppIdentity

# Grant it specific permissions (not Contributor)
az role assignment create \
  --role "Storage Blob Data Reader" \
  --assignee-object-id $(az identity show -g myResourceGroup -n myAppIdentity --query principalId -o tsv) \
  --scope /subscriptions/SUB_ID/resourceGroups/myRG/providers/Microsoft.Storage/storageAccounts/myStorage
```

## GCP

### Find overprivileged service accounts

```bash
# List all service accounts in a project
gcloud iam service-accounts list --project PROJECT_ID

# Check what roles a service account has
gcloud projects get-iam-policy PROJECT_ID \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:SA_EMAIL" \
  --format="table(bindings.role)"

# Find service accounts with Owner or Editor roles
gcloud projects get-iam-policy PROJECT_ID \
  --flatten="bindings[].members" \
  --filter="bindings.role:(roles/owner OR roles/editor)" \
  --format="table(bindings.members, bindings.role)"
```

### Use IAM Recommender to right-size permissions

```bash
# List IAM recommendations (requires recommender API enabled)
gcloud recommender recommendations list \
  --project PROJECT_ID \
  --location global \
  --recommender google.iam.policy.Recommender

# Apply a recommendation
gcloud recommender recommendations mark-claimed \
  --project PROJECT_ID \
  --location global \
  --recommender google.iam.policy.Recommender \
  --recommendation RECOMMENDATION_ID
```

### Workload Identity Federation (avoid service account keys)

For workloads running outside GCP (CI/CD, on-prem), use Workload Identity Federation instead of downloading JSON key files:

```bash
# Create a workload identity pool
gcloud iam workload-identity-pools create github-pool \
  --location global \
  --display-name "GitHub Actions Pool"

# Create a provider for GitHub Actions
gcloud iam workload-identity-pools providers create-oidc github-provider \
  --location global \
  --workload-identity-pool github-pool \
  --issuer-uri "https://token.actions.githubusercontent.com" \
  --attribute-mapping "google.subject=assertion.sub,attribute.repository=assertion.repository"

# Grant the identity access to specific resources
gcloud iam service-accounts add-iam-policy-binding SA_EMAIL \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-pool/attribute.repository/my-org/my-repo"
```

## Cross-Cloud Audit Checklist

Run this audit quarterly:

- [ ] All admin/owner roles are assigned to named individuals (not shared accounts)
- [ ] Service accounts use managed identities or workload federation (not static keys)
- [ ] No service account has admin/owner/contributor on the entire subscription/project
- [ ] Access keys and service account keys have been rotated in the last 90 days
- [ ] MFA is enforced for all human users with console access
- [ ] Break-glass accounts exist and are monitored but not used for daily work
- [ ] Cross-account/cross-project trust relationships are documented and reviewed
- [ ] IAM recommendations from cloud-native tools have been reviewed
- [ ] Unused identities (no activity in 90+ days) are disabled or deleted
- [ ] Conditional access policies restrict admin access to corporate networks/devices

## Tools

- **AWS IAM Access Analyzer**: Built-in, identifies unused permissions and external access
- **Azure Privileged Identity Management**: Just-in-time admin access
- **GCP IAM Recommender**: Suggests permission right-sizing based on actual usage
- **Prowler**: Open-source multi-cloud security assessment
- **ScoutSuite**: Multi-cloud security auditing
- **CloudSploit**: Cloud configuration monitoring

---

From [AllSecurityNews.com](https://allsecuritynews.com) - Your hub for cybersecurity intelligence.
