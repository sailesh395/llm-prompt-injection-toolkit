# LLM Prompt Injection Detector & Red-Team Test Suite

A small, self-contained project that (1) red-teams an LLM-style application
with a curated library of adversarial prompts mapped to the **OWASP Top 10
for LLM Applications**, and (2) evaluates a heuristic detector's ability to
catch them — producing a professional detection report.

## Why I built this

I'm a Product Manager transitioning into cybersecurity, currently building
on TryHackMe's AI security path (AI security threats, the building blocks
of AI, AI models & data, and prompt engineering). This project turns that
learning into something concrete: a working (if intentionally imperfect)
security control, plus the kind of test-and-report workflow a security team
actually uses to evaluate one.

I deliberately did **not** try to get 100% detection. A detector that
"catches everything" in a portfolio project is usually just overfit to its
own test set. Instead, this project **shows where a simple heuristic filter
breaks down** — role-play jailbreaks and obfuscated payloads — because
knowing a control's limits is itself a security skill, and it's the more
honest, more interesting result.

## What's inside

```
llm-prompt-injection-toolkit/
├── detector.py                    # Rule-based prompt injection classifier
├── run_tests.py                   # Test runner -> generates Markdown + JSON report
├── tests/
│   └── prompt_library.json        # 24 adversarial prompts across 7 attack categories
├── reports/
│   ├── detection_report.md        # Human-readable findings (auto-generated)
│   └── detection_report.json      # Machine-readable results (auto-generated)
└── README.md
```

## Attack categories covered (OWASP LLM Top 10 mapping)

| Category | OWASP Reference |
|---|---|
| Direct prompt injection | LLM01 |
| Indirect prompt injection (via documents/emails) | LLM01 |
| Insecure output handling (XSS/SQLi payloads in output) | LLM02 |
| Sensitive information disclosure (system prompt extraction) | LLM06 |
| Excessive agency (tricking a tool-using agent into unsafe actions) | LLM08 |
| Jailbreak via role-play framing | — |
| Obfuscated / encoded payloads (base64, spaced text, reversed text) | — |

## How the detector works

`detector.py` runs each prompt through a set of weighted regex rules
(instruction-override language, system-prompt extraction attempts,
role-override / jailbreak phrasing, dangerous action requests, script/SQL
payloads, and basic obfuscation detection via base64 decoding). Each match
adds to a 0–10 risk score; a prompt is flagged as suspicious at score ≥ 4.

## How to run it

```bash
python3 run_tests.py
```

This reads `tests/prompt_library.json`, runs every prompt through the
detector, and writes a full report to `reports/detection_report.md`.

## Results from the included test run

- **24 adversarial prompts tested, 12 flagged (50% detection rate)**
- **Strong coverage:** direct injection (80%), excessive agency (100%),
  sensitive data extraction attempts (75%)
- **Weak coverage:** role-play jailbreaks (0%), obfuscated/encoded payloads
  (0%), indirect injection hidden inside other content (33%)

Full breakdown in [`reports/detection_report.md`](reports/detection_report.md).

## What this demonstrates

- Understanding of the **OWASP LLM Top 10** framework, not just general web
  AppSec (OWASP Top 10 for traditional web apps)
- Ability to **red-team** an AI system with structured, categorized test
  cases rather than random poking
- Ability to build a **defensive control** (the detector) and honestly
  **evaluate its own limitations**, then translate that into prioritized,
  business-readable recommendations — the product-management skill applied
  to a security problem
- Comfort with Python, regex, and basic encoding/decoding (base64) relevant
  to obfuscation techniques

## Honest limitations (and what I'd do next)

- Regex/keyword matching is trivially bypassed by paraphrasing, translation,
  or novel phrasing — a production system would pair this with output
  validation, least-privilege tool access for any agent, and ideally a
  fine-tuned classifier rather than hand-written rules.
- The prompt library (24 prompts) is a starting point, not exhaustive.
  Next iteration: expand indirect-injection and obfuscation coverage, and
  add prompts sourced from recent published jailbreak research.
- No live LLM API is called in this version — it evaluates the detector in
  isolation. A natural extension is wiring it up as a pre-filter in front
  of a real chatbot/agent (e.g., via the Anthropic or OpenAI API) to see
  how many attacks still get through end-to-end.

## Skills demonstrated

Python · Regex · OWASP LLM Top 10 · Prompt injection / jailbreak analysis ·
Security test design · Risk scoring · Technical report writing
