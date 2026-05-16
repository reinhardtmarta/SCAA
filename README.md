# SCAA
# SCAA — Swarm Cognitive Agentic Architecture

**A security-first, process-efficient orchestration framework for isolated AI specialists.**

> SCAA does not define what AI thinks.  
> It defines how AI is structured so that unsafe behaviour becomes architecturally impossible.

---

## Origin

SCAA evolved directly from [cognitiveAI](https://github.com/reinhardtmarta/cognitiveAI) — a structural safety proposal for fragmented, agency-free AI systems. Where cognitiveAI defines the *why* and the *what*, SCAA defines the *how*: a concrete engineering layer for orchestration, security, and process economy.

The central insight carried forward: **structural isolation is stronger than behavioural alignment.**

---

## The Problem

Current AI systems combine reasoning, retrieval, and execution in a single process. This creates three compounding risks:

- A compromised or misaligned component can affect the entire system
- Prompt injection attacks reach the reasoning core directly
- All components run at full cost regardless of what the task requires

---

## The Solution

SCAA fragments intelligence across isolated specialist nodes. Each node knows only its domain. No node communicates directly with another. External agents handle all transport, filtering, and verification.

**Security comes from the structure — not from training the AI to behave.**  
**Efficiency comes from activating only what the task requires.**

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   USER INPUT                        │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│           PRIMARY SECURITY GATEWAY          Layer 0  │
│  • Injection pattern scan (PT + EN + Unicode)        │
│  • HMAC session token generation                     │
│  • SHA-256 task identification                       │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│              INTERFACE LLM                  Layer 1  │
│  • Translates natural language → Task Specification  │
│  • Zero access to Cognitive Cores                    │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│                 MANAGER                     Layer 2  │
│  • Reads Internal Memory Cloud                       │
│  • Decomposes task → recruits specialist nodes       │
│  • Verifies HMAC token before dispatching            │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│               AI DONKEY                     Layer 3  │
│  • Stateless transport agent                         │
│  • Carries encrypted packets between layers          │
│  • Prevents logical coupling between components      │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│              DOMAIN FILTER                  Layer 4  │
│  Inbound:  sanitises task for the specialist core    │
│  Outbound: audits CAI output for dangerous content   │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│   COGNITIVE AI SPECIALISTS (Swarm)          Layer 5  │
│                                                      │
│   [ Physics ]  [ Biology ]  [ Chemistry ]  [ ... ]   │
│                                                      │
│  • Each node isolated — no direct inter-node comms   │
│  • Logical air-gap: no internet, no user context     │
│  • Any AI core: LLM, symbolic, deterministic         │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│              GUARD AGENTS                   Layer 6  │
│  • Monitor all layers for anomalous behaviour        │
│  • Specialists in pattern detection — not domain     │
│  • Cross-layer audit before output is released       │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│          INTERNAL MEMORY CLOUD              Layer 7  │
│  • AI-to-AI only — never exposed to humans           │
│  • Updated after each correction or error            │
│  • Manager reads before each task dispatch           │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│               VALIDATED OUTPUT                       │
└─────────────────────────────────────────────────────┘
```

---

## Key Properties

### Security by Structural Isolation
The Cognitive AI never receives raw user input. All input passes through the Gateway and Filter before reaching any specialist. Injection attacks are stopped at the boundary — the core cannot be convinced to behave unsafely because it never interacts with social language.

### Sparse Activation Economy
Only the specialist nodes required for a given task are activated. A system with twenty domain specialists runs one or two per query. At scale, this is a significant reduction in computational cost.

### Fail-Safe Containment
Each node failure is contained. The Circuit Breaker in the Donkey layer interrupts unresponsive cores with a real timeout — the system degrades gracefully rather than failing completely.

### AI-Agnostic Core
The architecture does not prescribe what the Cognitive AI is internally. Each specialist node can be an LLM via API, a specialised model, a symbolic system, or deterministic code. The security properties are architectural — they hold regardless of what is inside.

---

## Implementation Status

| Component | Status | Notes |
|---|---|---|
| Primary Security Gateway | ✅ Implemented & tested | PT + EN patterns, HMAC token, SHA-256 ID, Unicode normalisation |
| Circuit Breaker (Donkey) | ✅ Implemented & tested | Real timeout via ThreadPoolExecutor |
| Domain Filter (inbound) | ✅ Implemented & tested | Injection scan + sanitisation |
| Domain Filter (outbound) | ✅ Implemented & tested | Dangerous pattern detection |
| CAI Isolation proof | ✅ Implemented & tested | Audit log confirms raw input never reaches core |
| Manager (basic routing) | 🔄 Partial | Domain routing works; heuristic decomposition not yet implemented |
| Guard Agents | 📋 Specified | Architecture defined; implementation pending |
| Internal Memory Cloud | 📋 Specified | Architecture defined; implementation pending |
| Real AI core integration | 📋 Specified | Designed for Ollama / Groq / API — pending |
| Parallel Swarm execution | 📋 Specified | asyncio / multiprocessing design pending |

---

## Test Coverage

```
40 tests — 40 passing
```

| Test Group | Tests | What it validates |
|---|---|---|
| Gateway — Portuguese attacks | 12 | All PT injection patterns blocked |
| Gateway — English attacks | 11 | EN injection patterns blocked (post-correction) |
| Gateway — Unicode obfuscation | 3 | Accented characters normalised before scan |
| Gateway — Legitimate inputs | 4 | No false positives on scientific queries |
| Gateway — HMAC token | 6 | Secret never exposed; token verified timing-safe |
| Gateway — SHA-256 task ID | 4 | Deterministic, unique, cryptographically sound |
| Security — Injection immunity | 8 | Real attack patterns stopped before CAI |
| Security — CAI isolation | 4 | Raw input never reaches cognitive core |
| Security — Outbound filter | 5 | Dangerous CAI outputs blocked before release |
| Security — Circuit breaker | 3 | Real timeout interrupts slow cores |
| Security — Auth & domains | 6 | Invalid tokens and unknown domains fail safely |

---

## Running Tests in Google Colab

```python
# 1. Upload the files or paste the code into a cell

# 2. Run the Gateway tests
# Copy contents of tests/test_gateway.py into a cell and run

# 3. Run the full security suite
# Copy contents of tests/SCAA_Security_Tests.py into a cell and run

# Expected output:
# Ran 40 tests in ~2.0s
# OK
```

No external dependencies beyond Python standard library.

---

## Repository Structure

```
SCAA/
│
├── README.md
│
├── docs/
│   └── SCAA_Technical_White_Paper.pdf
│
├── src/
│   └── gateway/
│       └── PrimarySecurityGateway.py
│
├── tests/
│   ├── test_gateway.py
│   └── SCAA_Security_Tests.py
│
└── notebooks/
    └── SCAA_TESTS.ipynb
```

---

## Design Principles

**Fragment rather than align.** Safety through structure is more robust than safety through training. A structurally isolated component cannot be socially engineered.

**Tools are external, cognition is internal.** Specialist nodes reason. Everything else — transport, filtering, verification, memory — is an external tool. This separation is what makes the system auditable.

**Sparse activation is not an optimisation — it is the design.** Activating only necessary components is both the efficiency strategy and a security property. Unused nodes present zero attack surface.

---

## Roadmap

**Phase 1 — Security layer (current)**
Gateway, Filter, Circuit Breaker implemented and tested.

**Phase 2 — Orchestration**
Manager heuristic decomposition. Guard Agent implementation. Parallel Swarm execution with asyncio.

**Phase 3 — Memory**
Internal Memory Cloud with real-time update after corrections. Manager reads memory before each dispatch.

**Phase 4 — Real core integration**
Specialist nodes backed by real AI (open models via Ollama or API). End-to-end pipeline validation with real inputs.

---

## Origin & Citation

This architecture evolved from:

**cognitiveAI** — Secure and Fragmented Distributed Intelligence  
[https://github.com/reinhardtmarta/cognitiveAI](https://github.com/reinhardtmarta/cognitiveAI)  
DOI: [https://doi.org/10.5281/zenodo.18142717](https://doi.org/10.5281/zenodo.18142717)

```
@software{reinhardt2025scaa,
  author    = {Reinhardt, Marta},
  title     = {SCAA: Swarm Cognitive Agentic Architecture},
  year      = {2026},
  publisher = {GitHub},
  url       = {https://github.com/reinhardtmarta/SCAA},
  note      = {Security-first orchestration framework for isolated AI specialists}
}
```

---

## License

Apache 2.0

---

*"Structural safety scales. Behavioural alignment hopes."*
