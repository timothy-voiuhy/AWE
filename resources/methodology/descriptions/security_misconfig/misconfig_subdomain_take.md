# Subdomain Takeover

## Overview
Subdomain takeover occurs when a subdomain's DNS record points to an external service (GitHub Pages, Heroku, S3, Netlify, Azure, etc.) that is no longer claimed or configured. An attacker registers the external resource and takes control of the subdomain — serving content from the organization's domain, potentially stealing cookies, bypassing CSP, or conducting phishing under the trusted domain.

## How It Works
- Company creates `staging.target.com` pointing to `myapp.herokuapp.com` via CNAME.
- The Heroku app is later deleted/decommissioned but the DNS CNAME record remains.
- `myapp.herokuapp.com` is now unclaimed — anyone can register a Heroku app with that name.
- Attacker registers `myapp.herokuapp.com`, taking control of `staging.target.com`.
- The attacker now serves content from `staging.target.com` — same domain, full trust.

## Impact
- Hosting phishing pages under a trusted domain.
- Stealing session cookies if `Domain=.target.com` cookies are sent to all subdomains.
- XSS on other pages via same-origin cookie theft from the taken subdomain.
- Bypassing CSP: if `staging.target.com` is in the CSP allowlist, attacker controls a script source.
- Email phishing from `staging.target.com` email addresses.
- Bypassing CORS: if the subdomain is in the CORS allowlist.

## Where to Look
- DNS records: CNAMEs pointing to external services.
- Subdomains with HTTP 404 errors from the external service (e.g., Heroku's "No such app").
- Acquired or decommissioned services that left DNS records intact.
- Development, staging, preview, and beta subdomains.
- Services with "dangling CNAME" patterns: `CNAME → unclaimed.{service}.com`.

**Vulnerable services (non-exhaustive):**
```
GitHub Pages → username.github.io (404 "There isn't a GitHub Pages site here")
Heroku → myapp.herokuapp.com (404 "No such app")
Netlify → myapp.netlify.com (404)
Azure Websites → myapp.azurewebsites.net
AWS S3 → mybucket.s3-website.us-east-1.amazonaws.com (NoSuchBucket)
Shopify → myapp.myshopify.com (Sorry, this shop is currently unavailable)
Fastly → (CNAME pointing to unclaimed Fastly zone)
Ghost → ghost.io unclaimed subdomain
Readme.io → old project subdomain
Surge.sh → unclaimed surge project
```

## Testing Steps
1. Enumerate subdomains using passive OSINT and active brute-forcing.
2. For each subdomain, check the DNS CNAME chain: `dig CNAME staging.target.com`.
3. Request the subdomain — check the response for fingerprints of unclaimed resources ("No such app", "NoSuchBucket", "404" from known services).
4. Identify which external service the CNAME points to.
5. Check if the external resource is unclaimed (free to register).
6. If unclaimed, register the external resource to confirm takeover feasibility (in bug bounty context — do NOT host malicious content, just verify and report).
7. Document the CNAME chain, the HTTP response fingerprint, and the external service name.

## Payloads / Techniques
```bash
# Enumerate subdomains
subfinder -d target.com -o subdomains.txt
amass enum -passive -d target.com >> subdomains.txt
assetfinder target.com >> subdomains.txt

# Check DNS CNAME
for sub in $(cat subdomains.txt); do
  cname=$(dig +short CNAME $sub)
  if [ ! -z "$cname" ]; then
    echo "$sub -> $cname"
  fi
done

# Check HTTP response for takeover fingerprints
httpx -l subdomains.txt -title -status-code -follow-redirects -o results.txt
grep -i "No such app\|NoSuchBucket\|404\|There isn't a GitHub Pages" results.txt

# Using subjack
subjack -w subdomains.txt -t 100 -o takeover_candidates.txt -ssl

# Nuclei subdomain takeover templates
nuclei -l subdomains.txt -t ~/nuclei-templates/takeovers/
```

## Burp Suite Tips
- Burp is not the primary tool here — subdomain discovery and DNS tooling are more relevant.
- After confirming a takeover, use Burp to test cookie scope and CORS impact.

## Tools
- subfinder — https://github.com/projectdiscovery/subfinder
- amass — https://github.com/owasp-amass/amass
- subjack — https://github.com/haccer/subjack (automated takeover detection)
- nuclei + takeover templates — https://github.com/projectdiscovery/nuclei-templates/tree/main/takeovers
- can-i-take-over-xyz — https://github.com/EdOverflow/can-i-take-over-xyz

## Remediation
- Remove or update DNS records for decommissioned services immediately.
- Maintain a DNS record inventory with service ownership — audit quarterly.
- Implement a subdomain monitoring process to detect dangling CNAMEs.
- Use short TTLs on DNS records for external services to speed up removal.
- Before decommissioning any external service, remove its DNS record first.

## References
https://portswigger.net/web-security/host-header/exploiting/lab-host-header-subdomain-takeover
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover
https://github.com/EdOverflow/can-i-take-over-xyz
https://0xpatrik.com/subdomain-takeover/
