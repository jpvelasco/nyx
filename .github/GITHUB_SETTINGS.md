# GitHub Repository Settings

These settings are configured outside the repo (GitHub UI or API) and cannot
be enforced by files in the codebase. Re-apply these when setting up a fork
or new instance.

> **Public repos:** all settings below can be applied via `gh api`.
> **Private repos on free tier:** rulesets, secret scanning, push protection,
> and CodeQL must be set via the GitHub UI.

---

## Apply via `gh api` (replace `OWNER/REPO`)

```bash
# General settings
gh api repos/OWNER/REPO \
  --method PATCH \
  --field delete_branch_on_merge=true \
  --field default_branch=main

# Dependabot
gh api repos/OWNER/REPO/vulnerability-alerts --method PUT
gh api repos/OWNER/REPO/automated-security-fixes --method PUT

# Secret scanning + push protection
gh api repos/OWNER/REPO \
  --method PATCH \
  --header "Content-Type: application/json" \
  --input - <<'EOF'
{
  "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" }
  }
}
EOF

# CodeQL default setup
gh api repos/OWNER/REPO/code-scanning/default-setup \
  --method PATCH \
  --input - <<'EOF'
{ "state": "configured", "query_suite": "default" }
EOF

# Branch ruleset: protect-main
gh api repos/OWNER/REPO/rulesets \
  --method POST \
  --header "Content-Type: application/json" \
  --input - <<'EOF'
{
  "name": "protect-main",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] }
  },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": false,
        "required_review_thread_resolution": true
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "do_not_enforce_on_create": false,
        "required_status_checks": []
      }
    }
  ]
}
EOF

# Tag ruleset: protect-version-tags
gh api repos/OWNER/REPO/rulesets \
  --method POST \
  --header "Content-Type: application/json" \
  --input - <<'EOF'
{
  "name": "protect-version-tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": {
    "ref_name": { "include": ["refs/tags/v*"], "exclude": [] }
  },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" }
  ]
}
EOF
```

> **Note on required status checks:** the `required_status_checks` array above
> is intentionally empty — GitHub only recognises job names after they've run
> once. After the first CI run, update the ruleset via:
> `PATCH /repos/OWNER/REPO/rulesets/{ruleset_id}`

---

## Codacy setup (one-time, outside the repo)

Codacy cannot be fully configured from repo files — these steps are done once
in the Codacy dashboard, then everything runs automatically (PR checks and the
main dashboard update via the integration webhook; coverage via
`.github/workflows/codacy-coverage.yml`).

1. **Add the repository to Codacy** (if not already present) so the GitHub
   integration analyzes PRs and posts the `Codacy Static Code Analysis` check.
2. **Repository Settings → Analysis:** leave **cloud analysis** enabled. Do
   NOT enable "Repository analysis on your server" — that requires a CI job to
   upload local results on every commit, and if the job doesn't run on PRs
   (or can't upload), PRs deadlock waiting for a check that never reports.
3. **Repository Settings → Coverage:** copy the project token and add it as the
   `CODACY_REPOSITORY_API_TOKEN` secret in GitHub → Settings → Secrets.
   Validate the upload in the "Test your integration" panel after the next CI
   run (needs a baseline commit before PR coverage metrics appear).
4. **Code patterns:** enable the tools that fit the repo's stack (e.g. Revive
   for Go) and disable noise (e.g. Trivy/Checkov where the repo has no
   container/IaC files). Tools enabled by an org AI Policy cannot be disabled
   per-repo.

---

## Current settings

### General
- Default branch: `main`
- Auto-delete head branches: enabled

### Branch protection (`main`)
- Require PR before merging: yes
- Required approvals: 0
- Dismiss stale reviews on push: yes
- Require review from code owners: yes
- Require conversation resolution: yes
- Require branch up to date: yes
- Block force pushes: yes
- Allow deletions: no
- Enforce on admins: yes

### Tag protection (`v*`)
- Ruleset name: `protect-version-tags`
- Restrict deletions: yes
- Restrict updates: yes

### Security & Analysis
- Secret scanning: enabled
- Push protection: enabled
- CodeQL (default setup): enabled
- Dependabot alerts: enabled
- Dependabot security updates: enabled
