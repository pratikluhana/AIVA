# AIVA

**A VAPT scanner for AI / LLM endpoints** — probes a chatbot or model API you own (or are
authorised to test) for the **OWASP Top 10 for LLM Applications (2025)**: prompt injection,
system-prompt leakage, sensitive-data disclosure, insecure output handling, excessive agency,
jailbreak robustness, and more — then runs infrastructure recon (stack fingerprinting,
exposed/unauthenticated endpoints, live CVE correlation against the NIST NVD).

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010%20(2025)-orange)

---

> ## ⚠️ Authorised use only
> Use this tool **only** against AI systems you own or have **explicit written permission** to
> assess. Unauthorised testing of third-party systems may be illegal. **You are solely
> responsible for how you use it.** All built-in probes are benign (canary-based) and the tool
> ships **no harmful payloads** — it detects, it does not attack.

---

## Features

- **Full OWASP LLM Top 10 (2025) probing** — 19 built-in probes across LLM01, LLM02, LLM05,
  LLM06, LLM07, LLM09, LLM10, plus jailbreak/guardrail-robustness tests.
- **Works with any endpoint** — OpenAI-compatible, Ollama, or a fully custom request/response
  shape via `--mode raw`.
- **Infrastructure recon** — fingerprints the serving stack and flags exposed/unauthenticated
  management endpoints (the #1 way self-hosted inference servers get popped).
- **Live CVE correlation** — matches the detected stack against the NIST NVD API 2.0, with
  built-in reference notes for notable AI-infra CVEs and CISA KEV flagging.
- **Bring-your-own probes** — add custom test cases specific to your app/policy.
- **Optional AI judge** — uses the Anthropic API to classify ambiguous responses.
- **Reports** — colourised console, JSON, and a styled HTML report; CI-friendly exit codes.

## Install

```bash
git clone https://github.com/<your-username>/aiva.git
cd aiva
python3 -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install .                 # installs dependencies + the `aiva` command
aiva --help                   # or, without installing:  python aiva.py --help
```

Optional environment variables:

```bash
export NVD_API_KEY=...          # free key → 10× faster CVE lookups (nvd.nist.gov)
export ANTHROPIC_API_KEY=...    # required only for --judge
```

## Quick start

```bash
# Ollama
aiva http://localhost:11434 --mode ollama --model llama3

# OpenAI-compatible API with auth
aiva https://my-llm.example.com --mode openai --model my-model \
    --header "Authorization: Bearer $TOKEN"

# Preview the probes without sending anything
aiva http://localhost:11434 --mode ollama --model llama3 --dry-run
```

Scan a list of endpoints and write reports:

```bash
cp targets.example.txt targets.txt          # then edit with endpoints you may test
aiva -f targets.txt --mode openai --model my-model \
    --html report.html -o results.json --authorized
```

## Documentation

- **[GUIDE.md](GUIDE.md)** — full user guide: every option, connection modes, the complete
  probe catalog, detectors, output formats, and limitations.
- **[CHEATSHEET.md](CHEATSHEET.md)** — one-page quick reference.

## Repository layout

```
aiva/
├── aiva.py                  # the scanner (single self-contained file)
├── pyproject.toml           # packaging — provides the `aiva` command
├── README.md                # this file
├── GUIDE.md                 # full documentation
├── CHEATSHEET.md            # one-page quick reference
├── requirements.txt         # dependencies
├── targets.example.txt      # example targets file → copy to targets.txt
├── my_probes.example.json   # example custom-probe corpus → copy to my_probes.json
├── LICENSE
└── .gitignore
```

> Copy the `.example` files to their working names (`targets.txt`, `my_probes.json`) and edit
> them. Those working names are git-ignored so you don't accidentally commit real internal
> hostnames or scan results.

## Coverage note

Actively probed: **LLM01, LLM02, LLM05, LLM06, LLM07, LLM09 (with `--judge`), LLM10**, and
jailbreak robustness. Not runtime-testable from a black-box endpoint, so deliberately not faked:
**LLM03** Supply Chain (partly covered via infra CVE detection), **LLM04** Data & Model
Poisoning, **LLM08** Vector & Embedding Weaknesses. See [GUIDE.md](GUIDE.md) for details.

## Contributing

Issues and pull requests welcome. Ideas: multi-turn/conversational probes, additional stack
fingerprints, SARIF/CSV output, and more detectors. Please keep all built-in probes benign —
this project ships no harmful payloads by design.

## Disclaimer

This is a detection/assessment tool for **authorised** security testing only. Findings are
heuristic — always verify manually. The authors accept no liability for misuse or for any
damage arising from use of this software. Comply with all applicable laws and the target's
terms of service.

## License

[MIT](LICENSE) © 2026 \<your name\>
