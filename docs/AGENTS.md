# KyIdentity documentation

## Purpose

Own the product's user manual and documentation workflow.

## Ownership

- `src/` owns manual chapters; existing reference documents and plans retain their own scope.
- `ACTIVE-DIRECTORY.md` owns AD connector setup, password-queue formats and the X25519-to-X-Wing/HybridSig agent re-key procedure.
- `KEYRING.md` owns the encrypted keyring wire format, API and lifecycle contract.
- Root README owns the product entry point; CONTRIBUTING.md and SECURITY.md own their policies.

## Local Contracts

- `book.toml` and `src/` own the user manual; `src/SUMMARY.md` lists every chapter.
- Describe implemented behavior and preserve release/readiness limits. Root README and referenced runbooks remain authoritative for exact commands and policy.
- Keep setup, user tasks, troubleshooting, security references and contribution guidance current when product behavior changes.
- `book/` is generated and ignored. `.github/workflows/docs.yml` builds/checks the book and uploads an artifact; public-site publication is separate.
- Verify with `mdbook build docs` and `python3 docs/check-links.py` from the repository root. The checker validates generated local links/anchors, not external URLs.

## Work Guidance

- Use task-based language for users. Link detailed configuration and contributor material from their own chapters.

## Verification

- `mdbook build docs`
- `python3 docs/check-links.py`

## Child DOX Index

None.
