# Secure coding guide

Approach code like an attacker: assume every input is hostile and every control can be
bypassed. Principles that run through everything below:

- **Validate server-side.** Client checks are UX, not security.
- **Fail closed.** On error or doubt, deny.
- **Least privilege.** Grant the minimum, revoke promptly.
- **Defense in depth.** Never rely on a single control.
- **Encode for context.** Data is dangerous when it crosses into a new interpreter (HTML, SQL, shell, URL).

---

## 1. Access control

The most common and most damaging web bug class. Authorization must be enforced **at the data
layer**, on **every** request — not just hidden in the UI or checked at the route.

**Check**
- Does the current user own / have rights to *this specific* resource id?
- Multi-tenant: is the resource in the user's org/tenant?
- Role actions: is the role re-validated server-side (never trusted from the client/token claims alone)?
- Parent ownership: accessing a child (comment) verifies the parent (post) too.

**Pitfalls**
- **IDOR** — `/api/orders/123` returns any order. Always scope queries by owner.
- **Privilege escalation** — accepting a client-supplied `role`/`isAdmin`.
- **Mass assignment** — binding the whole request body to a model (`User(**body)`); allow-list fields.
- **Horizontal / vertical** access — user A reads user B; normal user hits admin route.

**Secure pattern**
```python
def get_order(order_id, user):
    order = db.orders.find(order_id)
    if not order or order.owner_id != user.id:
        return http_404()   # 404, not 403 — don't reveal existence
    return order
```
Prefer non-guessable ids (UUIDv4) over sequential ones. On user removal/deactivation, revoke
sessions and API keys immediately (use short-lived tokens + revocation list).

**Checklist:** ☐ ownership checked at data layer ☐ org/tenant scoped ☐ role re-validated ☐ field allow-list ☐ 404 on unauthorized.

---

## 2. Cross-site scripting (XSS)

Untrusted data rendered without context-correct encoding executes as script.

**Input sources** — form fields, query/hash params, headers, third-party API data,
`postMessage`, storage values, filenames, Markdown/SVG uploads, error messages reflecting input.

**Protect**
- **Output-encode for the context:** HTML body, HTML attribute, JS, URL, and CSS each need
  different encoding. Use the framework's escaping (React JSX, Vue `{{ }}`, Django autoescape).
- **Avoid raw-HTML sinks:** React `dangerouslySetInnerHTML`, Vue `v-html`, `innerHTML`. If
  unavoidable, sanitize with a vetted library (DOMPurify).
- **Content-Security-Policy** as a second layer: `default-src 'self'`, no `unsafe-inline`.
- Sanitize SVG uploads (they can carry script); render user Markdown without raw HTML.

**Checklist:** ☐ framework escaping on ☐ no unsanitized raw-HTML sink ☐ CSP set ☐ uploads/Markdown sanitized.

---

## 3. Cross-site request forgery (CSRF)

State-changing requests must prove they came from your app, not an attacker's page.

- Use the framework's **anti-CSRF token** for cookie-authenticated POST/PUT/DELETE.
- Set session cookies `SameSite=Lax` (or `Strict`), plus `HttpOnly`, `Secure`.
- Pure token-in-header APIs (Authorization: Bearer) are generally not CSRF-able — but cookie
  auth always is.

**Checklist:** ☐ CSRF token on state changes ☐ `SameSite` cookies ☐ safe methods are side-effect-free.

---

## 4. Secrets & sensitive data

- **Never** hardcode API keys, passwords, tokens, connection strings. Load from env / secret manager.
- Keep `.env` out of git (`.gitignore`); scan history for leaks (gitleaks).
- Don't log secrets, tokens, or full PII. Redact.
- Encrypt sensitive data at rest; always TLS in transit.

**Checklist:** ☐ no secrets in code ☐ `.env` gitignored ☐ secrets not logged ☐ TLS enforced.

---

## 5. Open redirect

User-controlled redirect targets enable phishing and can leak tokens.

- Allow-list redirect destinations; or only permit relative paths.
- Reject absolute URLs to other hosts; normalize before checking (block `//evil.com`, `\/\/`,
  backslashes, and IDN/Unicode look-alikes).

```python
def safe_redirect(target):
    if not target.startswith("/") or target.startswith("//"):
        return "/"          # only same-site relative paths
    return target
```

---

## 6. Authentication, sessions, passwords

- **Passwords:** hash with bcrypt/argon2/scrypt (never MD5/SHA-1, never plaintext). Enforce
  length over arbitrary complexity; check against breach lists.
- **Sessions:** regenerate id on login (prevent fixation); `HttpOnly`+`Secure`+`SameSite`
  cookies; idle + absolute timeouts; invalidate on logout and password change.
- **Brute force:** rate-limit and lock/backoff on repeated failures; throttle MFA attempts.
- **Account lifecycle:** on deactivation/removal, kill all sessions and API keys at once.

**Checklist:** ☐ strong password hash ☐ session id regenerated on login ☐ secure cookies ☐ rate limiting ☐ sessions revocable.

---

## 7. JWT

- Pin the algorithm server-side; **reject `alg: none`** and unexpected algs (prevents
  alg-confusion, e.g. RS256→HS256).
- Verify signature, `exp`, `iss`, `aud` on every request.
- Keep access tokens short-lived; use refresh tokens + a revocation/denylist (JWTs can't be
  "un-issued").
- Never put secrets in the payload (it's only base64, not encrypted).

**Checklist:** ☐ alg pinned ☐ `none` rejected ☐ exp/iss/aud verified ☐ short TTL + revocation.

---

## 8. Server-side request forgery (SSRF)

The server is tricked into making requests to internal targets.

- Allow-list outbound hosts/schemes; block private/link-local ranges
  (`127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `::1`).
- **Block cloud metadata endpoints** (`169.254.169.254`, GCP/Azure equivalents).
- Resolve DNS and validate the **resolved IP** (guard against DNS rebinding); disable
  auto-following redirects to bypass the check.
- Fetch user-supplied URLs through a constrained proxy, not the app's network identity.

**Checklist:** ☐ host/scheme allow-list ☐ private + metadata ranges blocked ☐ resolved-IP checked ☐ redirects controlled.

---

## 9. Insecure file upload

- Validate type by **content** (magic bytes), not just extension or `Content-Type`.
- Store outside the web root; generate random names; never execute uploads.
- Cap size; scan archives (zip-bomb / path traversal in entries).
- Serve with `Content-Disposition: attachment` and a correct, safe content type.

**Checklist:** ☐ content-based type check ☐ stored non-executable, random name ☐ size limit ☐ safe serving headers.

---

## 10. SQL / NoSQL injection

- **Always parameterize** (prepared statements / ORM bound params). Never build queries by
  string concatenation or interpolation.
- Validate/allow-list anything that can't be a parameter (e.g. column/table names, sort order).
- NoSQL: reject operator objects in user input (`{"$gt": ""}`); cast types.

```js
// before
db.query(`SELECT * FROM u WHERE email = '${email}'`);
// after
db.query("SELECT * FROM u WHERE email = $1", [email]);
```

---

## 11. XML external entities (XXE)

- Disable DTDs and external entity resolution in the XML parser.
- Prefer JSON; if XML is required, use a hardened parser config (`defusedxml` in Python,
  `setFeature(disallow-doctype-decl, true)` in Java).

---

## 12. Path traversal

- Never concatenate user input into file paths. Resolve and confirm the result stays within
  an allowed base directory.

```python
base = Path("/srv/data").resolve()
target = (base / user_path).resolve()
if base not in target.parents:
    raise Forbidden()
```
- Strip/deny `..`, absolute paths, and URL-encoded variants.

---

## 13. Security headers

Set globally: `Content-Security-Policy`, `Strict-Transport-Security`,
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (or CSP `frame-ancestors`),
`Referrer-Policy: no-referrer`, and a least-privilege `Permissions-Policy`. Cookies:
`HttpOnly; Secure; SameSite`.

---

## 14. API & GraphQL

- **Object-level + function-level authZ** on every endpoint (see §1) — the #1 API risk.
- **Mass assignment:** explicit input DTO / field allow-list.
- **Rate limiting** and pagination caps to prevent abuse/enumeration.
- **GraphQL:** disable introspection in prod (or restrict), limit query depth/complexity,
  enforce authZ per resolver, avoid leaking internal errors.

---

## Framework notes

- **React:** JSX auto-escapes; the risk is `dangerouslySetInnerHTML` (sanitize). Don't put
  secrets in client bundles / `NEXT_PUBLIC_*`.
- **Vue:** `{{ }}` escapes; `v-html` does not (sanitize).
- **Node/Express:** `helmet` for headers; parameterized DB drivers; validate with zod/joi.
- **Python/Django/Flask:** templates autoescape; use the ORM (parameterized); `defusedxml`;
  `SECURE_*` settings + `SECRET_KEY` from env.
- **.NET:** Entity Framework parameterizes; `[ValidateAntiForgeryToken]`; Data Protection API
  for secrets.

---

## General principles

Keep the attack surface small, default to deny, log security events (without sensitive data),
keep dependencies patched, and re-check authorization whenever privileges change. When unsure
whether something is exploitable — treat it as if it is.
