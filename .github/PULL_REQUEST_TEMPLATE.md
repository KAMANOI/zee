<!--
Thanks for taking the time to send a PR. A few things to know up
front because Zee is run as a "seeded OSS" (see CONTRIBUTING.md):

  * PRs are welcome but not required. If `git fetch upstream &&
    git rebase` is too much friction, just keep your fork.
  * If your change is "this fix made Zee work in my environment",
    the highest-leverage place to post it is actually a Discussion
    under https://github.com/KAMANOI/zee/discussions/categories/q-a
    (searchable by the next person hitting your OS / locale).
  * If you do want it upstream, fill this template and the CI
    matrix will validate it across Linux / macOS / Windows.
-->

## What changed

A one-paragraph description of the change.

## Why

What problem does this solve / what scenario does it unlock?

## Type of change

- [ ] Bug fix in the reference implementation
- [ ] OS-shift fix (a `docs/maintenance/` template would also be a
      great place to write this up, if it might recur)
- [ ] New test (no behaviour change)
- [ ] Documentation / `docs/maintenance/` / `CONTRIBUTING.md` /
      Wiki seed
- [ ] Something else (please describe)

## Tests

- [ ] `pytest tests/ -q` is green on my machine
- [ ] CI matrix is green on the PR

## みんなで防災 — anything to share?

If this change came out of a real-world experience (OS update,
industry-specific deployment, locale, …), consider linking a
Discussion or Wiki page so others can find your write-up:

- Discussion / Wiki link (optional):

---

By submitting, you confirm the contribution is under the MIT License.
