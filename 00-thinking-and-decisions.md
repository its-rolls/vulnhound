# VulnHound — Milestone 0: How to think about a scanner

This is our running notebook. Each milestone gets its own file. Decisions go in the
**Decision log** at the bottom with the alternatives we rejected, because interviewers
ask "why did you pick X?" far more often than "what does X do?".

> Only scan targets you own or are explicitly allowed to test. In this project that means
> DVWA and OWASP Juice Shop running on your own machine (localhost).

---

## 1. The mental model: every web scanner is four steps

```
 DISCOVER  ──►  ATTACK  ──►  OBSERVE  ──►  REPORT
 (crawler)     (payloads)   (detectors)   (findings)
```

1. **Discover**: find every place the app takes input. Links, forms, URL parameters,
   cookies, headers. You can't test what you haven't found, so the crawler limits
   everything after it.
2. **Attack**: send a crafted value into each input. For XSS that's something like
   `<script>alert(1)</script>`. For SQL injection it's a `'` or `' OR SLEEP(5)--`.
3. **Observe**: decide if the attack worked. Did the payload come back unescaped in the
   HTML? Did the database print an error? Did the page take 5 seconds longer?
   This is the hardest part, and it is where false positives come from.
4. **Report**: turn raw observations into findings a human can act on: what, where,
   how bad (CVSS), how to fix.

Some checks skip step 2 completely. "Missing security headers" or "exposed `.git` folder"
are **passive** or **request-only** checks. They are easy, so we build them first
to prove the plumbing works before tackling the tricky injection checks.

## 2. The design idea that makes it a *real* project: plugins

A beginner version is one big file with `if xss... if sqli...`. The professional
version is a small **engine** plus many **checks**, where each check follows the same
contract:

```
Check:
  name, severity
  run(target_page) -> list of Findings
```

The engine handles crawling, concurrency, rate limiting and reporting. A check only
knows how to test one thing. Adding a new check never touches the engine. This is
exactly how Nuclei, ZAP and Burp extensions are organised, and it is the single
best thing to talk about in an interview.

## 3. Milestone plan (small steps, each one runnable)

| # | Milestone | You'll have at the end |
|---|-----------|------------------------|
| 1 | Lab setup | DVWA + Juice Shop running in Docker on localhost |
| 2 | Skeleton + CLI | `vulnhound scan http://localhost:8080` prints "hello" with proper flags |
| 3 | Scoped crawler | A list of every page, form and parameter on the target, staying in scope |
| 4 | Plugin interface + easy checks | Headers, exposed files, directory listing findings |
| 5 | XSS + SQLi | Real injection findings on DVWA, false positives measured |
| 6 | Auth, concurrency, rate limiting | Scans pages behind a login, fast but polite |
| 7 | Reports + CVSS | JSON and HTML report |
| 8 | CI mode + benchmark | GitHub Action that fails on high severity; "found X of Y" numbers for the README |

---

## Decision log

### D1. Language: Python (decided)

| Option | For | Against |
|--------|-----|---------|
| **Python** | Fastest to write; huge security ecosystem (requests, httpx, BeautifulSoup); most pentest scripts are Python; easy to read in an interview | Slower; concurrency is via `asyncio`, which has a learning curve |
| **Go** | Real tools use it (Nuclei, httpx, ffuf, gobuster); goroutines make concurrency easy; ships as one binary | More boilerplate; slower to iterate while you're still learning the security side |
| Rust | Fast and safe | Steep learning curve; you'd spend the project fighting the compiler instead of learning web security |
| JavaScript/Node | Good with Playwright | Weaker security tooling ecosystem; less common in pentest roles |

**Reasoning:** the hard, valuable part of this project is the *security* thinking
(detection logic, false positives), not raw speed. A scanner is network-bound, so it
spends most of its time waiting for responses anyway; async Python is fast enough.
If you already know Go well, Go is the stronger resume signal.

**Decision:** Python, since you're at beginner-to-moderate level. A Go rewrite of the
hot path is a good stretch goal later ("rewrote the crawler in Go, 4x faster" is a great
resume line).

### D2. Practice targets: DVWA + OWASP Juice Shop in Docker

| Option | Why / why not |
|--------|---------------|
| **DVWA** | Classic PHP app with *known* XSS/SQLi at adjustable difficulty. Perfect for checking your detector actually fires. |
| **Juice Shop** | Modern JavaScript app with 100+ documented challenges. Great for the "found X of Y" benchmark. |
| WebGoat | Good, but more of a teaching course than a scan target. |
| Real websites | Illegal without written permission. Never. |

**Docker** because each target starts with one command, is isolated from your machine,
and resets to a clean state when you delete it.
