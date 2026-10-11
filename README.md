# infra-risk-reviewer (P02 L3 sandbox)

This is a dedicated sandbox for the P02 Infrastructure PR Risk Reviewer, used only for the Mode A live acceptance tests (L3).

- **Synthetic fixtures only.** Everything under `p02-demo/` is hand-written test data. There is no real infrastructure, no real plan and no credentials.
- **The workflow `.github/workflows/p02-review.yml` runs on `pull_request` only.** It has read-only permissions, uses no secrets and requests no OIDC token. It never runs Terraform or Helm and calls no external model.
- **A green result is not approval.** It means "no blocking findings by the baseline rules", and is never a safety approval.
- Nothing here is deployed or applied anywhere.

Sandbox note: docs-only change for L3.
