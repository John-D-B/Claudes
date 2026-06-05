# CLAUDE-AI-Coding-Terminology.md

AI Assisted Development: Terminology and Spectrum

**Author:**  John Buehrer (JohnB), with AI pair-programming support by Anthropic Claude<br/>
**Date:**  2026-03-19 (CertGrep v4.1.0 session)<br/>


## The Spectrum

### Vibe Coding  *(junior / casual end)*
You describe what you want in natural language, accept whatever the AI
produces, minimal review.  Fast but fragile.  The term carries a
slightly pejorative edge among serious developers, implying you don't
fully understand what you're shipping.

### AI Assisted Coding  *(neutral, broad)*
You write most of the code; AI helps with boilerplate, syntax, and
lookups.  Copilot-style autocomplete lives here.  The human is clearly
still the driver.

### AI Pair Programming  *(the middle ground)*
You hold the architecture and requirements; AI does the implementation;
you review and direct.  The human is the senior engineer, AI is a very
fast junior who never sleeps and occasionally needs to be corrected
about path traversal pitfalls.

### AI Agentic Coding  *(autonomous end)*
Claude Code / Cursor / Devin territory.  The AI operates autonomously
over longer horizons: reads the whole repo, plans multi-step changes,
runs tests, iterates.  You set goals; AI executes.  Less
turn-by-turn supervision.


## Where CertGrep Development Sits

Between **AI Pair Programming** and **AI Agentic Coding**, with a notable
characteristic: explicit session hygiene (handover docs, version
discipline, deliberate context management).  That's actually more
sophisticated than most agentic setups, which just throw the whole
repo at the AI and hope.

Emerging terms for this style:
- *Supervised agentic development*
- *Directed AI development*

Neither has fully stuck yet in the industry.

**Cocktail-party sound bite:**

> "In project CertGrep, JohnB does AI pair programming with structured session management."

Accurate, sounds intentional, and "structured" signals that you know what
you're doing.


## JohnB's "Farm of Robots" Model

One subscription, multiple independent AI sessions, each isolated:
no direct cross-session awareness.<br/>
Each session gets:

- The latest code from GitLab (source of truth)
- Handover docs (CLAUDE-*.md) for project context
- A specific work unit scoped to fit within one session

Session transitions are not a failure mode, they're a shift change.<br/>
Work results carry forward, even when the conversation doesn't.

This is more descriptive than most industry terminology.

*Written by the CertGrep v4.0.0 / v4.1.0 Claude session.*<br/>
*See also: **CLAUDE-prompt-eng.md** for operational session guidance.*
