# Coverage: what this machine can prove, and with what

Read the rows for the classes this code is in, not the file top to bottom.
A row names the verdict the class can reach on a machine that has the
repository and a shell, and what turns a suspicion into a finding. A proof
the machine does not have is the verdict "needs what is not here", said in
the answer, never quietly dropped.

## The four verdicts

| verdict | in the answer |
|---|---|
| proved | the input was run and the code did the wrong thing; the command, its output and the line are quoted |
| named | the source shows it and no run reached it; the answer says which half a run would have to show |
| needs what is not here | a second identity, a device, a deployment or an outbound callback; named, with the class out of scope until it exists |
| not checked | the class was never looked at; said as not checked, never as passed |

## A value reaching an interpreter, a path or a response

| class | verdict here | what proves it |
|---|---|---|
| command, SQL, template, code injection | proved | the payload from `references/defenses.md` sent through the real handler or its test, with the output that shows it executed |
| path traversal, archive members | proved | the path that resolves outside the root, printed by the same resolver the code uses |
| SSRF, redirect, id in a URL | proved for what leaves the box; blind SSRF needs an outbound callback | the request the server made, seen at the sink (a listener here, the log of the host it reached) |
| XSS, header, log injection | proved | the rendered page or the log line holding the value unescaped |
| upload | proved | a file whose stored name or served type differs from what was sent |
| regular expressions and other patterns that hang | proved | the pattern that hangs on a long input, run under a timeout |

## Identity, access and secrets

| class | verdict here | what proves it |
|---|---|---|
| authorization between users or tenants | proved only with two identities at different privileges | request A's resource with B's credential and read the response |
| authentication, sessions, tokens, reset flows | named from the source; proved when the endpoint runs here | the exchange, step by step, against the running service |
| a token's verification and binding | named from the source; proved when the service runs here | a forged token (`alg:none`, another issuer, `kid` into a path) sent to the running endpoint |
| session lifecycle: rotation, termination, timeout | proved with the endpoints here | the cookie held before login, and the id after logout, replayed |
| the mode of a file the code writes | proved | `stat` / `icacls` on the file after the code wrote it |
| a secret in source, in a fixture or in a log line | proved | the search and the line it returned |
| crypto at rest, key management | named | the library and the mode it is called with; a run proves it where a stored artefact exists to decrypt |

## The running system

| class | verdict here | what proves it |
|---|---|---|
| misconfiguration and exposure (debug surface, CORS, defaults) | proved when the service runs here; named otherwise | the request to the exposed surface and its response |
| error paths and fail-open | proved | malformed input, a forced error, a timeout, and what the caller got back |
| supply chain: a version with a known weakness | proved for the version, and for the runtime's version as the deploy reports it; named for the build | the lock file's version, and `php -v` / `node --version` / the image tag, against the advisory, with the advisory's id |
| CI/CD and release trust | needs what is not here | the pipeline's own run; the answer stops at the repository |
| logging and alerting | not provable from here | nothing on this machine shows whether an alert fires; said as out of scope, never as passed |

## Design and logic

| class | verdict here | what proves it |
|---|---|---|
| business logic: price and quantity tampering, workflow skipping | proved when the case can be sent here | the sequence of requests that skips a step or changes a total |
| trust between components, deserialization of internal data | named | the boundary the value crosses and what parses it |
| a design that is insecure rather than a line that is wrong | named, and the judgement that goes with it | the abuse case written out, and whether it can be run here |

A verdict is what the answer says, not a statement that the class is safe.
"needs what is not here" and "not checked" are results too, and each claim in
the answer is only as strong as what was proved.
