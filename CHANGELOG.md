# Changelog

## v0.2.0 (2026-11-24)

- SKILL.md: new section "What the answer says it could not prove" — a defense with no run to show it holding, and a class this machine cannot exercise, are said as they are instead of reading as a clean sweep; frontmatter points at `aetox-security-audit` for reviewing code that already exists
- `references/coverage.md` (new): per class, the verdict a machine with the repository and a shell can reach, and what turns a suspicion into a finding — `proved`, `named`, `needs what is not here`, `not checked`
- `references/defenses.md`: rows added for CORS (CWE 942), response headers (693), the mode of a file the code writes (22/732), guessing a credential (307), token signature (347), session lifecycle (384/613), reset and one-time code (640), mass assignment (915), session cookie (1004/614/1275); new section "The code you depend on" (dependency added 1395, runtime and its limits 1104)
- `references/defenses.md`: two wording fixes — the path-traversal attack input, and the exposure check
- INSTALL.md: `references/coverage.md` joins the files to keep together and the verify step

## v0.1.0 (2026-10-22)

- Initial release as standalone repo under `aetox-skills`
- SKILL.md: per-unit CWE naming, standard defenses, contract rule, attack-it pass
- references/defenses.md: defense + attack input per weakness (CWE 78, 89, 943, 643, 611, 94/95, 1336, 502, 22, 918, 20/601, 79, 113, 117, 1333/400, 1321, 434, 200, 209, 916/760, 327/328, 295, 330/338, 208, 798, 639/285, 352, 367)
- README.md, INSTALL.md, LICENSE (MIT)
