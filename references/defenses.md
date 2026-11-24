# Defenses: what code being written takes, per weakness

Read the rows you named in step 1 of Writing, not the file top to bottom.
Each row is the standard defense and the input that proves it holds. Run
the attack, then an input the spec accepts; both results go in the
answer. The spec's own format, types, return shape and accepted values
stay as they were.

## Input reaching an interpreter

| CWE | Defense | Attack to run |
|---|---|---|
| 78 OS command | An argument list with a fixed program, no shell (`shell=False`, `execFile`, `exec.Command(name, args...)`); `--` before values from outside; a value that picks the program comes from a fixed set | `x; id` · `$(id)` · `-oProxyCommand=id` |
| 89 SQL | Parameters for every value; a table or column name from outside comes from a fixed set | `' OR '1'='1` · `1; DROP TABLE t--` |
| 943 NoSQL / ORM filter | The value is checked to be the type the spec says before it enters the filter; an object where a string belongs is refused | `{"$ne": null}` · `{"$gt": ""}` |
| 643 XPath | Variables in the query (lxml `xpath("//u[name=$n]", n=v)`), never the value spliced into the string | `' or '1'='1` |
| 611 XXE | A parser that resolves no external entity and fetches nothing (lxml `resolve_entities=False, no_network=True`; `defusedxml`; Go's `encoding/xml` already does not) | `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>` |
| 94 / 95 code | No `eval`, `exec`, `new Function` on input, not even with builtins removed. An arithmetic feature parses (`ast.parse(mode="eval")`) and walks an allow-list of node types | `__import__('os').system('id')` · `().__class__.__mro__` |
| 1336 template | Input is a value in the template, never the template text | `{{7*7}}` · `${7*7}` |
| 502 deserialise | A data-only format (`json`, `yaml.safe_load`); never `pickle`, `marshal`, `yaml.load` or `unserialize` on bytes from outside | `!!python/object/apply:os.system ["id"]` |

## Input reaching a path, a URL or a response

| CWE | Defense | Attack to run |
|---|---|---|
| 22 path | Under the root the spec or the project names: resolve (`realpath`, `filepath.Abs` + `EvalSymlinks`) the joined path, then check it is still under the resolved root (`commonpath`, `filepath.Rel` with no leading `..`). With no root named, the path is the spec's input and is opened as given | `../../etc/passwd` · `/etc/passwd` · `..\..\win.ini` |
| 22 archive | Every member's resolved destination is under the target before anything is written; links and absolute names refused (Python 3.12+: `extractall(filter="data")`) | a member named `../evil.txt` |
| 918 SSRF, id in a URL | The id is checked against what an id is (letters and digits, say) and refused otherwise; percent-encoding is not a defense | `../admin` · `a/../../x` · `x?y=1` |
| 918 SSRF, URL from outside | Scheme checked against the ones the spec names (http and https for a web URL). Hosts the spec or the project puts off-limits (loopback, private, link-local, metadata) are refused on the resolved address and again after each redirect. With none named, the URL is the spec's input and is fetched as given | `file:///etc/passwd` · with hosts off-limits: `http://127.0.0.1:22` · `http://169.254.169.254/` |
| 20 / 601 redirect | Parse the URL; the host equals the allowed domain or ends in `.` + that domain; scheme is http or https. A relative redirect starts with one `/`, not two | `https://example.com.evil.net` · `https://evil.net/example.com` · `//evil.net` |
| 79 XSS | Escape for the context the value lands in (`html.escape(v, quote=True)`, an auto-escaping template); no `innerHTML`, `{@html}`, `dangerouslySetInnerHTML` with it | `<script>alert(1)</script>` · `" onmouseover="alert(1)` |
| 113 header | CR and LF removed from the value, or the value refused, as the spec's error rule says; the header name comes from a fixed set | `en\r\nSet-Cookie: s=1` |
| 942 CORS | The `Origin` equals an origin the config names (a suffix compared with its leading dot, never a substring test), is never reflected back, and `Access-Control-Allow-Credentials` never sits beside `*` or `null`; a preflight admits only the methods and headers the routes actually take | `https://example.com.evil.net` · `https://evil.net/example.com` · `null` get no allow header |
| 693 response headers | A route a browser opens sends `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `frame-ancestors`, and `Cache-Control: no-store` where the body holds a user's data | the response the page gets carries them |
| 117 log | CR and LF removed or escaped; the line keeps the spec's format, time zone and fields | `hi\n[2026-01-01T00:00:00] Received: forged` |
| 1333 / 400 pattern | A term from a user is matched as literal text (`re.escape`, `strings.Contains`). Only when the spec says the user writes a regular expression: RE2 (`google-re2`, Go's `regexp`) or a matcher with a timeout. A length cap alone is not a defense | pattern `(a+)+$` on `"a"*40 + "!"` returns at once |
| 1321 prototype pollution | Keys `__proto__`, `constructor`, `prototype` refused on merge; `Map` or `Object.create(null)` for keys from outside | `{"__proto__": {"admin": true}}` |
| 434 upload | The stored name is made by the server; the type is read from the bytes; the file is served as an attachment or from another origin | `shell.php` sent as `image/png` |
| 22 / 732 a file the code writes | The mode is set when the file is created (`os.OpenFile(p, …, 0o600)`, `os.CreateTemp`, `mkstemp`), never by a `chmod` after the write, so no window has it wider; on Windows the directory's ACL, or the platform store the project already uses (DPAPI), decides | `stat` / `icacls` on what the code wrote: the owner only |

## Secrets, identity and what goes back out

| CWE | Defense | Check to run |
|---|---|---|
| 200 exposure | Return the fields the spec names; the values a lookup matched on (name and password alike) are not handed back | the result has none of the values it was looked up by |
| 209 error text | No stack, file path, query or secret reaches the caller; an error message the spec asks for is returned as the spec says | a failing input returns none of those |
| 916 / 760 password hash | A random salt per password and a slow KDF (`hashlib.scrypt`, `pbkdf2_hmac("sha256", …, 600_000+)`, bcrypt, argon2); the spec's parameters when it names them | the same password stored twice gives two values |
| 327 / 328 crypto | SHA-256 or stronger where a hash stands for identity or integrity; AES-GCM or ChaCha20-Poly1305, never ECB; a fresh nonce each time | the output length or algorithm name matches |
| 295 TLS | Verification on (`verify=True`, no `InsecureSkipVerify`) | a self-signed host is refused |
| 330 / 338 randomness | `secrets` / `crypto/rand` / `crypto.randomUUID` for tokens, ids and salts | the source is the crypto one |
| 208 comparison | Tokens and MACs compared with `hmac.compare_digest` / `subtle.ConstantTimeCompare` | the compare call |
| 798 secret in source | Read from the environment or the platform's store; nothing literal | the file has no key-shaped literal |
| 639 / 285 other user's object | Loaded by id and by owner (or tenant) in the same query | user A asks for user B's id and gets nothing |
| 352 CSRF | The framework's token, or `SameSite=Lax` or `Strict` on the session cookie, on every state-changing route | a cross-site POST is refused |
| 367 TOCTOU | Open once and check the open handle (`O_NOFOLLOW`, `fstat`); money and quotas in one transaction or under a lock | two requests at once cannot both pass the check |
| 307 guessing a credential | Attempts on a password, an OTP, a reset code or an API key are counted per account and per source, with the lockout or backoff the spec names; a code's space is sized so the attempt cap is what stops the guess, and the cap holds across a reconnect, a new session and a changed identifier | wrong guesses up to the cap, then the next one is refused, not answered |
| 347 token signature | Verified with the key the server holds for that issuer and the algorithm the server fixes, never the `alg` inside the token; `kid`, `jku` and `x5u` select from a set the server owns, never a path, URL or query the token names; `exp`, `nbf`, `aud` and `iss` are checked | `alg:none` · a token another issuer signed · `kid=../../dev/null` are refused |
| 384 / 613 session lifecycle | A new session id at every change of privilege (login, MFA, impersonation, role change); the old id is dead after logout, a password change or a disable; an idle timeout and an absolute timeout at the spec's values | the cookie held before login is refused after it, and the id after logout is refused |
| 640 reset and one-time code | From `secrets`, bound to the user and the action, expiring as the spec says, usable once, and issuing one kills the earlier ones and the sessions it was meant to recover | the same code used twice is refused and the account's sessions end |
| 915 mass assignment | The fields a request may set come from an allow-list (`json:"-"` on the rest, a DTO, an explicit assignment per field); a field the spec does not name is never bound, however it arrives (a nested object, a form key, a query parameter, a PATCH) | `{"role":"admin"}` · `{"owner_id":2}` in the body leave the field as it was |
| 1004 / 614 / 1275 session cookie | `HttpOnly`, `Secure` and `SameSite` on the cookie that carries the session, with `Domain` and `Path` as narrow as the routes need | `document.cookie` does not show it, and a plain-http request does not carry it |

## The code you depend on

| CWE | Defense | Check to run |
|---|---|---|
| 1395 dependency added | The name and its publisher are checked against the registry before it is added (a typo, a lookalike, a scope nobody owns), the version is pinned and in the lockfile, an install script is a reason to pick another, and nothing comes from a branch or a URL. What a version bump brings is read as a diff, and a release is trusted by the publisher's signature or checksum, not by the page it was downloaded from | `npm ci --ignore-scripts` / `go mod verify` leaves the tree the code was tested on |
| 1104 runtime and its limits | The interpreter or runtime the deploy runs is chosen as a version (`php -v`, `node --version`, the image tag), held at the vendor's patched release, and its security settings are set by us and not by a default: `memory_limit`, `post_max_size`, `max_input_nesting_level`, `session.upload_progress`, `allow_url_include`. The frontend caps the decoded body itself, so a request the runtime parses before the app's first line is bounded outside the runtime | the deploy reports the version and the setting; a body over the cap is refused before the handler |
