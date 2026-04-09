# Kubernetes Security Hardening Guide

A practical guide to securing Kubernetes clusters. Covers the misconfigurations that actually get exploited, with commands you can run today.

## 1. API Server Security

The API server is the front door to your cluster. Lock it down first.

### Restrict API server access

```bash
# Check if your API server is publicly accessible
kubectl cluster-info
# If the endpoint is a public IP, it needs to be behind a VPN or private network
```

**For managed clusters (EKS, AKS, GKE):**
- Enable private cluster endpoints
- Restrict API server access to your VPN/office CIDR blocks

**For self-managed:**
Add to your API server configuration:
```yaml
# Restrict to specific CIDRs
--authorization-mode=RBAC,Node
--anonymous-auth=false
--enable-admission-plugins=NodeRestriction,PodSecurity
```

### Disable anonymous authentication

```bash
# Check if anonymous auth is enabled
kubectl auth can-i --list --as system:anonymous
# If this returns anything other than "no", anonymous auth is on
```

## 2. RBAC: Least Privilege

RBAC misconfigurations are the most common Kubernetes security issue. Most clusters have over-permissioned service accounts and overly broad ClusterRoles.

### Audit current permissions

```bash
# Find all ClusterRoleBindings that grant cluster-admin
kubectl get clusterrolebindings -o json | jq -r '
  .items[] |
  select(.roleRef.name == "cluster-admin") |
  .metadata.name + " -> " + (.subjects[]? | .kind + "/" + .name)
'

# Find service accounts with broad permissions
kubectl auth can-i --list --as system:serviceaccount:default:default

# List all roles and what they can do
kubectl get roles --all-namespaces -o json | jq -r '
  .items[] |
  .metadata.namespace + "/" + .metadata.name + ": " +
  ([.rules[].verbs[]] | join(","))
'
```

### Create least-privilege roles

Instead of granting `cluster-admin`, create specific roles:

```yaml
# Example: Read-only role for a monitoring service account
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: monitoring-reader
  namespace: production
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch"]
```

### Stop using the default service account

Every pod gets the `default` service account unless you specify one. Create dedicated service accounts:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: production
automountServiceAccountToken: false  # Only mount if the app needs it
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
      automountServiceAccountToken: false
```

## 3. Pod Security

### Enforce Pod Security Standards

Kubernetes has built-in Pod Security Standards (PSS) that replace the deprecated PodSecurityPolicy. Apply them at the namespace level:

```bash
# Enforce restricted standard (recommended for production)
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted

# For namespaces that need more flexibility (CI/CD, monitoring)
kubectl label namespace monitoring \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/warn=restricted
```

### Security context for every pod

Always define a security context:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: my-app
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL
        resources:
          limits:
            cpu: "500m"
            memory: "256Mi"
          requests:
            cpu: "100m"
            memory: "128Mi"
```

Key points:
- `runAsNonRoot: true` prevents containers from running as root
- `readOnlyRootFilesystem: true` prevents writing to the container filesystem
- `capabilities.drop: ALL` removes all Linux capabilities
- Always set resource limits to prevent resource exhaustion attacks

## 4. Network Policies

By default, all pods can talk to all other pods. This is bad. Implement network segmentation:

### Default deny all traffic

```yaml
# Apply to every namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

### Allow only what's needed

```yaml
# Allow frontend to talk to backend on port 8080
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080

---
# Allow backend to reach the database
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-backend-to-db
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
  # Also allow DNS
  - to: []
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
```

## 5. Secrets Management

### Never store secrets in plain text

```bash
# Check for secrets stored as environment variables in pod specs
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] |
  .metadata.namespace + "/" + .metadata.name + ": " +
  ([.spec.containers[].env[]? | select(.value != null) |
    select(.name | test("(?i)password|secret|key|token")) |
    .name] | join(", "))
' | grep -v ': $'
```

### Use external secrets management

Use the External Secrets Operator to pull secrets from HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: db-credentials
  data:
  - secretKey: username
    remoteRef:
      key: prod/database
      property: username
  - secretKey: password
    remoteRef:
      key: prod/database
      property: password
```

### Encrypt secrets at rest

Ensure etcd encryption is enabled:

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

## 6. Image Security

### Scan images before deployment

```bash
# Scan with Trivy
trivy image myregistry.com/my-app:latest

# Scan for critical and high vulnerabilities only
trivy image --severity CRITICAL,HIGH myregistry.com/my-app:latest
```

### Use minimal base images

```dockerfile
# Instead of this:
FROM ubuntu:22.04

# Use this:
FROM gcr.io/distroless/static-debian12

# Or for Go apps:
FROM scratch
```

### Enforce image policies

Use an admission controller to prevent unauthorized images:

```yaml
# Kyverno policy: only allow images from your private registry
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-image-registries
spec:
  validationFailureAction: Enforce
  rules:
  - name: validate-registries
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Images must come from myregistry.com"
      pattern:
        spec:
          containers:
          - image: "myregistry.com/*"
```

## 7. Audit Logging

### Enable audit logging

Create an audit policy:

```yaml
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
# Log authentication failures
- level: Metadata
  resources:
  - group: ""
    resources: ["pods", "services", "secrets"]
  verbs: ["create", "update", "patch", "delete"]

# Log all changes to RBAC
- level: RequestResponse
  resources:
  - group: "rbac.authorization.k8s.io"
    resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]

# Log exec into pods (potential backdoor access)
- level: RequestResponse
  resources:
  - group: ""
    resources: ["pods/exec", "pods/attach"]
```

### Monitor for suspicious activity

```bash
# Check for exec sessions (someone shelling into pods)
kubectl get events --all-namespaces --field-selector reason=ExecCreate

# Check for recently created service accounts
kubectl get serviceaccounts --all-namespaces --sort-by=.metadata.creationTimestamp | tail -10

# Check for privileged pods
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] |
  select(.spec.containers[].securityContext.privileged == true) |
  .metadata.namespace + "/" + .metadata.name
'
```

## 8. Quick Security Audit

Run this to get a quick snapshot of your cluster's security posture:

```bash
#!/bin/bash
echo "=== Kubernetes Security Quick Audit ==="
echo ""
echo "1. Cluster-admin bindings:"
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name == "cluster-admin") | "  " + .metadata.name'
echo ""
echo "2. Pods running as root:"
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[].securityContext.runAsUser == 0 or (.spec.securityContext.runAsNonRoot != true and .spec.containers[].securityContext.runAsNonRoot != true)) | "  " + .metadata.namespace + "/" + .metadata.name' | head -20
echo ""
echo "3. Pods with hostNetwork:"
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.hostNetwork == true) | "  " + .metadata.namespace + "/" + .metadata.name'
echo ""
echo "4. Namespaces without network policies:"
for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'); do
  count=$(kubectl get networkpolicies -n "$ns" --no-headers 2>/dev/null | wc -l)
  if [ "$count" -eq 0 ]; then echo "  $ns (no policies)"; fi
done
echo ""
echo "5. Pods without resource limits:"
kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.containers[].resources.limits == null) | "  " + .metadata.namespace + "/" + .metadata.name' | head -20
```

## Tools

- **kube-bench**: Run CIS Kubernetes Benchmark checks automatically
- **Trivy**: Scan images, IaC, and cluster misconfigurations
- **Falco**: Runtime threat detection for containers
- **Kyverno**: Policy engine for admission control
- **kubeaudit**: Audit manifests for security issues

---

From [AllSecurityNews.com](https://allsecuritynews.com) - Your hub for cybersecurity intelligence.
