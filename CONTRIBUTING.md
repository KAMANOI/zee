# Contributing to Zee

Thank you for considering a contribution. Zee is an
**Early Public / Research Project**: the API, the threat model, and even
the project's scope are still moving. Please assume nothing is stable
yet.

## Where to start

- **Have a question?** Open a GitHub Discussion.
- **Found a bug?** Open an Issue with a small reproduction.
- **Found a security issue?** Don't open a public issue. See
  [SECURITY.md](./SECURITY.md).
- **Want to propose a change?** Open an Issue first to discuss the
  direction before writing code. This avoids you putting in work on
  something the maintainer was about to redesign.

## Pull requests

1. Open or comment on an Issue first.
2. Fork, branch, and run `pytest` locally:
   ```bash
   pip install -e ".[test]"
   pytest tests/
   ```
3. Keep the change small and focused. One PR, one concern.
4. Follow the existing code style. Standard library only where possible
   (Zee has zero third-party runtime dependencies — standard library only.
5. Update tests for any behavior change.
6. If your change touches the **decoy templates** (`src/zee/decoy/seeder.py`),
   make sure new credential-like strings include `_` (underscore) so they
   do **not** match production secret-scanner regular expressions
   (Stripe `sk_live_[A-Za-z0-9]{24,}`, AWS `AKIA[0-9A-Z]{16}`). Splitting
   into adjacent string literals (`"AK" "IA..."`) keeps this source file
   itself scanner-clean.

## What changes are likely to be rejected

- Adding any third-party runtime dependency (Zee deliberately depends
  on the standard library only).
- Adding "defense rate" / "0% false positive" / containment-guarantee
  language to docs, comments, or commit messages. Zee deliberately does
  not make those claims.
- Auto-reconnect / auto-restore features. Recovery in Zee is manual by
  design.
- Adding any text that promises Zee can stop a given class of attacker
  (named or otherwise).

## Code of Conduct

By participating, you agree to follow the
[Code of Conduct](./CODE_OF_CONDUCT.md).

## License

By submitting a contribution, you agree that your work will be
distributed under the MIT License — the same license as the rest of the
project.
