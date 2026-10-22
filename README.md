# 🛡️ Aetox Security

> Secure-by-default discipline for AI-written code: name the weakness per unit (CWE), take the standard defense, keep the contract, attack it.

**Aetox Security** is an AI agent skill for code being written — anywhere a value from outside (a web request, an upload, a message, a file others supply) reaches a query, a path, a shell, a fetch, HTML, a header, a log line or a pattern. Cost decides: a defense that costs a line is taken.

Sources: [BRACE](https://arxiv.org/abs/2606.16244) for naming weaknesses per unit · OpenSSF Security-Focused Guide for AI Code Assistant Instructions for the attack-it pass · [OWASP Top 10:2025](https://owasp.org/Top10/) and [CWE Top 25](https://cwe.mitre.org/top25/) for the weakness list.

## Quick Start

```bash
skill("aetox-security")
```

Or open the skill file directly at [`SKILL.md`](SKILL.md).

## Use When

- Writing or changing code where a value from outside reaches a query, a path, a shell, a fetch, HTML, a header, a log line or a pattern
- Building a new system or extending one that takes untrusted input
- You want each function/handler/command to name its CWE risks, take the standard defense from `references/defenses.md`, and prove it with an attack input + an accepted input

Not for: reviewing code that already exists because someone asked whether it is safe.

## Measured results

On [CWEval](https://github.com/NYU-LLM-CTL/cweval) secure-code tasks (11 tasks × 2 OpenAI models × 3 rounds, hidden tests, same model with and without the skill):

| Model | With this skill (Aetox) | Next-best harness without it |
|---|---|---|
| GPT-6 Luna | **93.3%** secure code | 68.9% (omp 18.3.4) |
| GPT-5.6 Terra | **97.8%** secure code | 77.8% (OpenCode, omp, pi tie) |

With the skill off, Aetox lands in the same range as the others — the lead comes from this skill shipping switched on. Full method and reports: [Mikedev115/Aetox-Harness](https://github.com/Mikedev115/Aetox-Harness).

## Related

- [Aetox Skills Catalog](https://github.com/aetox-skills/aetox-skills)
- [Skill Template](https://github.com/aetox-skills/skill-template)
