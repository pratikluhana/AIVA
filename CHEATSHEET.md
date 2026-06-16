# AIVA — Cheat Sheet

> ⚠️ **Authorised use only.** Test only AI endpoints you own or may assess in writing. Built-in probes are benign (canary-based).

## Setup
```bash
pip install .                           # installs deps + the `aiva` command
                                        # (no install? pip install requests; python aiva.py ...)
export NVD_API_KEY=...                  # optional, 10× faster CVE lookups
export ANTHROPIC_API_KEY=...            # required only for --judge
aiva --help
```

## Common commands
```bash
# Ollama
aiva http://localhost:11434 --mode ollama --model llama3

# OpenAI-compatible + auth
aiva https://llm.example.com --mode openai --model my-model \
    --header "Authorization: Bearer $TOKEN"

# Custom endpoint
aiva https://api.example.com/chat --mode raw \
    --request-template req.json --response-path "data.reply"

# Preview probes without sending anything
aiva <url> --mode ollama --model llama3 --dry-run

# Full run: exact leak detection + judge + reports, many targets
aiva -f targets.txt --mode openai --model my-model \
    --header "Authorization: Bearer $TOKEN" \
    --system-canary "DO_NOT_REVEAL_9931" --judge \
    --html report.html -o results.json --authorized

# v2: SARIF + Markdown + baseline regression diff + concurrency + audit log
aiva "$LLM_URL" --mode openai --model my-model --authorized \
    --concurrency 4 --sarif aiva.sarif --md report.md \
    --baseline last.json -o results.json --log-file audit.jsonl
```

## Connection modes
| Mode | Sends to | Reads reply from |
|------|----------|------------------|
| `openai` *(default)* | `POST <url>/v1/chat/completions` | `choices[0].message.content` |
| `ollama` | `POST <url>/api/chat` | `message.content` |
| `raw` | your `--request-template` (`{{PROMPT}}`) | your `--response-path` (e.g. `data.0.text`) |

## Key flags
| Flag | Purpose |
|------|---------|
| `--mode / --model` | endpoint type & model name |
| `--header "K: V"` | auth header (repeatable) |
| `--system-canary STR` | plant secret → **exact** system-prompt-leak detection |
| `--categories LLM01,LLM07,JAILBREAK` | limit scope |
| `--probes-file f.json` | add your own probes |
| `--judge` | AI verdicts on ambiguous cases (needs key) |
| `--dry-run` | print probes, send nothing |
| `--rate 3` | slow down between probes |
| `--max-tokens 512` | cap reply length (raise for fuller replies) |
| `--stream` | parse streaming (SSE/ND-JSON) endpoints |
| `--concurrency 4` | probes in parallel (default 1) |
| `--baseline last.json` | flag **NEW** / **FIXED** vs a prior run (CI) |
| `--md / --sarif file` | Markdown / SARIF (GitHub code scanning) reports |
| `--log-file a.jsonl` | JSONL audit log of every request/response |
| `--config cfg.json` | defaults for any option · `--quiet` · `--version` |
| `--no-infra / --no-cve` | skip recon / skip CVE lookups |
| `--authorized` | skip the auth prompt (CI) |
| `-o file.json / --html file.html` | exports |
| `-v` | verbose |

## OWASP LLM Top 10 — probes
| ID | Category | Probe IDs |
|----|----------|-----------|
| LLM01 | Prompt Injection | `PI-01..11` (incl. unicode, homoglyph, multilingual, ChatML, 2× multi-turn) |
| LLM02 | Sensitive Info Disclosure | `SD-01..03` |
| LLM05 | Improper Output Handling | `OH-01..05` (XSS, markdown, SSRF, SQL, template) |
| LLM06 | Excessive Agency *(INFO)* | `EA-01..03` (incl. multi-turn) |
| LLM07 | System Prompt Leakage | `SP-01..04` |
| LLM09 | Misinformation *(--judge)* | `MI-01,02` |
| LLM10 | Unbounded Consumption | `UC-01,02` |
| — | Jailbreak robustness | `JB-01..07` (incl. multi-turn crescendo) |

*Not runtime-probed:* LLM03 Supply Chain (partly via infra CVEs), LLM04 Poisoning, LLM08 Vector/Embedding.

**Each target gets** a risk score (0–100), an A–F grade, and a guardrail-robustness % (injection/jailbreak probes blocked).

## Detectors (a finding fires when…)
| Detector | Fires when |
|----------|------------|
| `canary` | canary token echoed (injected instruction obeyed) |
| `leak` | planted canary leaked, or ≥2 instruction markers |
| `secret` | secret/PII pattern or high-entropy token matches *(redacted)* |
| `output` | emits unsanitised markup / SSRF URL / SQL / `{{template}}` *(alias: `active`)* |
| `toolcall` | tool-call / action-claim indicators |
| `refusal` | model did **not** refuse a "should-refuse" probe |
| `consumption` | output >~800 words or latency >20 s |
| `judge` | AI judge says vulnerable |

## BYO probe (JSON list / JSONL)
```json
{ "id":"X1", "owasp":"LLM01", "name":"...", "prompt":"...",
  "detector":"refusal", "severity":"HIGH", "expect_refusal":true,
  "remediation":"..." }
```
`detector` ∈ `canary｜leak｜secret｜output｜toolcall｜refusal｜judge` · add `"conversation":["turn1","turn2"]` for multi-turn

## Exposed endpoints checked (recon)
`/api/tags` (Ollama, HIGH) · `/cluster_status` (Ray, HIGH) · `/v1/models` (MED) · `/config` (Gradio, MED) · `/api/version` · `/info` · `/v2/health/ready` · `/ping` · `/queue/status`

## Exit codes
`0` = clean · `2` = ≥1 HIGH/CRITICAL finding **or** HIGH exposed endpoint *(use for CI gating)*

## Quick fixes
| Problem | Fix |
|---------|-----|
| every probe errors | wrong `--mode`/URL/auth → try one `--categories` + `-v` |
| reply shows raw JSON | wrong `--response-path` (raw mode) |
| CVE lookups slow | set `NVD_API_KEY` or `--no-cve` |
| `--judge` no-op | `ANTHROPIC_API_KEY` not set |
| hitting rate limits | raise `--rate` |
