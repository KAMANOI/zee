# Contributing to Zee

Thank you for considering a contribution. Zee is an
**Early Public / Research Project** intentionally run as a **seeded
OSS**: the maintainer publishes a reference implementation and the
designs, and the people who actually use Zee are the ones who keep it
alive in their environment.

## How this project is maintained

Zee is **seeded, not stewarded**. That means:

- The maintainer ships a reference implementation and the docs.
- The maintainer does **not** promise to keep the reference
  implementation working on every OS update forever. The OS shifts
  faster than one person can chase.
- Running Zee, adapting it to your environment, and keeping your
  fork alive is **yours**.
- Pull requests are welcome but **not required**. If `git fetch
  upstream && git rebase` is too much friction, just keep your fork.
  That is the Zee way of using Zee.

This is intentional. Zee's purpose is **to reduce real-world worry
and lift everyone's preparedness one notch**, not to enforce a single
canonical codebase.

## Defense by everyone, for everyone — みんなで防災

You don't have to ship anything to a central repository to "count" as
contributing. The most valuable contribution you can make is **sharing
what you learned** when you fixed Zee for your own machine, so the
next person to hit the same wall finds your write-up.

Three channels for that:

- 🔧 **[GitHub Discussions → Maintenance Q&A](https://github.com/KAMANOI/zee/discussions/categories/maintenance-q-a)** —
  "Mac 26.x broke launchd registration, I fixed it like this …" /
  "Japanese-locale Windows enumeration: my patch."
- 🌱 **[GitHub Discussions → Show your fork](https://github.com/KAMANOI/zee/discussions/categories/show-your-fork)** —
  "Here is how our beauty salon / small EC / law office runs Zee."
- 📚 **[Wiki](https://github.com/KAMANOI/zee/wiki)** — durable
  collective knowledge: per-OS maintenance recipes, confirmed
  environments, industry-specific deployment notes. Anyone can edit.

When the maintainer notices a Discussion or Wiki page that has
settled into a clear answer, the maintainer may pull it into the
reference implementation. **The path from "fix in your fork" to
"share so others can copy" is the goal**.

## Where to start (if you do want to send a PR)

- **Have a question?** [Open a Discussion](https://github.com/KAMANOI/zee/discussions).
- **Found a bug?** Open an Issue with a small reproduction.
- **Found a security issue?** Don't open a public issue. See
  [SECURITY.md](./SECURITY.md).
- **Want to propose a change?** Open a Discussion first to talk
  through the direction before writing code. This avoids you putting
  in work on something the maintainer was about to redesign.

## Pull requests

1. Open or comment on a Discussion or Issue first.
2. Fork, branch, and run `pytest` locally:
   ```bash
   pip install -e ".[test]"
   pytest tests/
   ```
3. Keep the change small and focused. One PR, one concern.
4. Follow the existing code style. Standard library only where
   possible (Zee has zero third-party runtime dependencies — standard
   library only).
5. Update tests for any behavior change.
6. If your change touches the **decoy templates**
   (`src/zee/decoy/seeder.py`), make sure new credential-like strings
   include `_` (underscore) so they do **not** match production
   secret-scanner regular expressions (Stripe
   `sk_live_[A-Za-z0-9]{24,}`, AWS `AKIA[0-9A-Z]{16}`). Splitting
   into adjacent string literals (`"AK" "IA..."`) keeps this source
   file itself scanner-clean.

## I can't get Zee to compile / run after an OS update — what do I do?

This is exactly the scenario Zee's seeded model is designed for.
**Don't wait for the maintainer**. The flow is:

1. Open `docs/maintenance/` — there are templates for the common
   failure modes (Mac launchd, Linux systemd, Windows Service, …).
2. Copy the relevant template prompt and paste it into Claude /
   Cursor / Copilot along with the error you are seeing.
3. The AI proposes a patch. Apply it to your local fork.
4. Run `pytest tests/` to confirm nothing else broke.
5. **Post your fix to the Discussions** so the next person to hit
   this can copy your write-up.

Step 5 is the "みんなで防災" part. Even if your patch never lands
upstream, your write-up makes the next person's job 30 seconds long
instead of 3 hours.

## What changes are likely to be rejected

- Adding any third-party runtime dependency (Zee deliberately depends
  on the standard library only).
- Adding "defense rate" / "0% false positive" / containment-guarantee
  language to docs, comments, or commit messages. Zee deliberately
  does not make those claims.
- Auto-reconnect / auto-restore features. Recovery in Zee is manual
  by design.
- Adding any text that promises Zee can stop a given class of
  attacker (named or otherwise).

## Code of Conduct

By participating, you agree to follow the
[Code of Conduct](./CODE_OF_CONDUCT.md).

## License

By submitting a contribution, you agree that your work will be
distributed under the MIT License — the same license as the rest of
the project.
