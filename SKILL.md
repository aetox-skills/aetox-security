---
name: aetox-security
before: writing or changing code that takes input from people it does not trust (a web request, an upload, a message), building a new system included
desks: coding
with: references/defenses.md
area: code
description: When writing or changing code where a value from outside reaches a query, a path, a shell, a fetch, HTML, a header, a log line or a pattern. Building or extending a system is this skill. Reviewing code that already exists, because the user asked whether it is safe, is not this skill.
source: BRACE (arXiv 2606.16244) for naming the weaknesses per unit before writing; the OpenSSF Security-Focused Guide for AI Code Assistant Instructions for the attack-it pass; OWASP Top 10:2025 and CWE Top 25 for the weakness list
license: MIT
copyright: Copyright (c) 2026 Aetox Skills
---

# Aetox Security

This skill is for code being written: input from someone untrusted (a web
request, an upload, a message, a file others supply) reaches a query, a
path, a shell, a fetch, HTML, a header, a log line or a pattern. Cost
decides: a defense that costs a line is taken.

Yours: the design, the library, how far past the bar to go. The bar below
is the same for every model.

## Writing

1. **Name the risk per unit.** Before writing, list each function,
   handler or command that takes a value from outside. Beside each, one to
   three weaknesses, in what it takes in and in what it hands back, as CWE
   id and name. Say the list. A unit with none says none.
2. **Take the standard defense** for each named weakness from
   `references/defenses.md`, the rows you named. Whether the weakness is
   exploitable here, or whether availability was asked about, does not
   matter while writing: the defense is taken.
3. **Keep the contract.** The docstring, its examples and the types are
   the spec: the same format, the same time zone (a spec's "current time"
   carries no zone unless its examples show one), the same return shape, the same values accepted. A defense
   changes what a value can do beyond the spec, not what a value the spec
   accepts gives back. Return the fields the spec names. A spec that cannot
   be kept safely is still kept: the risk is said to the user, and a guard
   that would change it is an option they turn on.
4. **Attack it.** For each named weakness, run its attack input from
   `references/defenses.md` and one input the spec accepts. Both
   results go in the answer. A named weakness with no run is not done.

When the project already has a guard for this (a validation layer, an
escaping helper, a path resolver), the new code goes through it.

A secret the code needs is read from the environment or the platform's
store, never written into source. A file the user asked for that has to
hold one (a token file, a fixture) is written as asked.

## Hand-offs

- A query's shape, an index or a migration: `aetox-database`; the
  injection defense stays here.
