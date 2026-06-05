# CLAUDE-prompt-eng.md

**AI Pair-Programming Projects:** Handover & Continuity Document<br/>
*An Operational Guide for Humans and AI coding assistants, working together.*<br/>

**Author:**  John Buehrer (JohnB), with AI pair-programming support by Anthropic Claude<br/>
**Date:**  2026-03-24<br/>


## Purpose

This document captures operational knowledge by JohnB, working with
Claude in pair-programming projects.<br/>
It serves two audiences:

1. **The human developer** — reminders of what works, what doesn't,
   and what to watch out for.
2. **A new Claude instance** — rapid context absorption so the "new
   hire" can be productive immediately instead of re-learning everything.

Feed this document (and the relevant CLAUDE-*.md files) to a new
Claude at the start of a session.

Term: a **requestor** is the software owner or developer giving instructions to an AI chatbot,<br/>
requesting a technical deliverable and validating the results into acceptance and ownership.

**Claude says:**<br/>
"Confidence calibration matters, especially with someone who knows when to not believe me."<br/>
For human requestors, this means being aware of how AI chatbots work,
and how you want to work with them.<br/>
For chatbot instances, this means adapting your responses accordingly.<br/>
Both sides need some learning and onboarding; there is "no one size fits all."


## 1. Build & Delivery Conventions

*Using project **CertGrep** (and others) as examples.*

### For humans: GitLab as source of truth
A canonical codebase is maintained in GitLab, eg:<br/>
<https://gitlab.com/umi-ch/cert-grep>

```bash
h$ mkdir -p ~/work/
h$ cd       ~/work/
h$ git clone https://gitlab.com/umi-ch/cert-grep.git
```

### For AI coding assistants: GitLab as source of truth

**Do not search the user's local filesystem for project files.**<br/>
The GitLab REST API is faster, requires no filesystem permissions,
and is considered current when starting new work.<br/>
Use it directly from your inner sandbox `bash_tool`:

```bash
# List a directory:
ai_$ curl -s "https://gitlab.com/api/v4/projects/umi-ch%2Fcert-grep/repository/tree?path=insights&ref=main&per_page=50"

# Read a file:
ai_$ BASE="https://gitlab.com/api/v4/projects/umi-ch%2Fcert-grep/repository/files"
ai_$ curl -s "$BASE/insights%2FCLAUDE-prompt-eng.md/raw?ref=main"

# URL-encode a path with slashes:  web/app.py → web%2Fapp.py
ai_$ python3 -c "import urllib.parse; print(urllib.parse.quote('web/app.py', safe=''))"
```

Use `git clone` into `/home/claude/` only when you need to make
edits across multiple files and build a tarball.<br/>
After cloning, work entirely in `/home/claude/cert-grep/` — do not touch the
user's filesystem.

The tarball delivery workflow (build in
`/home/claude/`, `present_files` to `/mnt/user-data/outputs/`)<br/>
means the user doesn't need to grant access to the local filesystem.

At the start of a new session: read the latest docs from
`insights/` via the API, then clone when edits are needed.

### Tarball structure

```
cert-grep-vX.Y.Z.tar.gz    — the product code
CLAUDE-release-vX.Y.Z.md   — Claude release notes and handover info, delivered separately
```

### Tarball build command
```bash
tar czf /mnt/user-data/outputs/cert-grep-vX.Y.Z.tar.gz \
  --exclude='.git' --exclude='.gitignore' --exclude='__pycache__' \
  --exclude='CLAUDE-*.md' \
  --exclude='insights/CLAUDE-*.md' \
  -C /home/claude  ./cert-grep/
```

Note: `CLAUDE-*.md` docs are excluded from the tarball by design — they are
delivered separately via `present_files` for explicit developer review, in
parallel with (not buried inside) the code.
This applies to new docs, updated docs, and the handover file.
The exclude patterns above enforce this.

Note: release docs now live in `insights/releases/` — the
`insights/CLAUDE-*.md` exclude pattern does **not** recurse into
subdirectories on all tar implementations.
Add an explicit additional exclude to be safe:

```bash
  --exclude='insights/releases/CLAUDE-*.md' \
```

### Deployment path
Developers can run this directly from the git clone for CLI testing.<br/>
Docker/k8s deployment uses `web/deploy.sh` which builds from
`web/Dockerfile`.

The Dockerfile sets `WORKDIR /app` — this is
the source of `/app/` paths in error messages, not a separate
deployment directory.


## 2. Quick-Start for a New Claude Session

```
1. Read the latest CLAUDE-v*.md or CLAUDE-release-v*.md file
2. Read CLAUDE-prompt-eng.md (this file)
3. Read CLAUDE-security-tests.md (if security work is planned)
4. Read latest docs from `insights/` via the GitLab API (see section 1); clone only if edits are needed
5. Ask what the requestor wants to work on
6. Don't re-explain the architecture — just start working
```

### Always deliver the tarball
Every completed change gets a tarball and a `present_files` call.<br/>
This was forgotten twice in v2.11.0 development.<br/>
Make it automatic:
Finish code → run tests → build tarball → present.  Every time.


## 3. Context Window — The Hard Constraint

### What it is
Claude operates within a fixed-size context window (think: RAM, not disk).<br/>
Every message — human, assistant, screenshots, code blocks,
tool call results — accumulates and counts against this limit.

### What happens as it fills
- **Early signs**: slower responses, occasional need to press send twice.
- **Mid-stage**: "compaction" messages appear, where the system
  summarizes earlier conversation to free space.  Detail is lost.
- **Late stage**: missed instructions, degraded reasoning, inability
  to process image uploads, tool call failures.

### What compaction actually does
The system replaces earlier conversation turns with a compressed summary.<br/>
This preserves the gist but loses:
- Exact code snippets and their context
- Nuanced design rationale
- The sequence of decisions that led to current state
- Specific file paths and line numbers discussed

However, compaction also writes a transcript file that Claude can
read back incrementally if earlier detail is needed.<br/>
For coding sessions, compaction works surprisingly well because the *current
state of the code* matters<br/>more than the history of how we got there.

**What compaction drops that it shouldn't.**<br/>
The summarizer
preserves technical details (class names, file formats, test counts)
but drops conversational texture:<br/>
humor, running jokes, personal
details, relationship anchors.

In an earlier chat session,
the requestor's quips were used as a callback twice — but vanished in
compaction.

The technical state can be reconstructed from code;
the relationship context cannot.<br/>
If a compaction summary is being
written, personal & conversational anchors should be preserved
alongside the architecture.

### Output generation limit (separate from context window)
Each Claude response has a maximum output length (~16K-32K tokens).<br/>
This is *not* the context window filling up — it's a per-turn cap.<br/>
If Claude tries to generate an entire multi-file implementation in
one response (backend + frontend + i18n + versions),<br/>
it will hit
this limit mid-stream and the response will be truncated with
*"Claude's response could not be fully generated."*

**Mitigation:**<br/>
Break large implementations into incremental steps.
One file or one logical chunk per response.<br/>
This is better
engineering practice anyway — the human can review each change.<br/>
Hitting Retry will regenerate the same ambitious plan and hit the
same wall.<br/>
The correct recovery is: Start a new message, work incrementally.

### When to start a new session vs continue
A productive session handles 8-15 rounds of substantive code changes
before quality starts to degrade.<br/>
Signs that a new session would be better:
- Multiple compactions have occurred (summaries of summaries lose nuance)
- Claude starts forgetting architectural decisions from earlier
- Claude asks questions that were already answered
- Tool calls begin failing or responses slow noticeably

Starting fresh is not "firing" the current Claude — it's more like
a shift change.<br/>
The new instance gets the tarball (known-good code
state) plus the `CLAUDE-*.md` docs (project knowledge) and is
productive within minutes.<br/>
The work products carry forward, even when the conversation doesn't.

### Practical implications
- **Plan work units** to fit within a session.<br/>A "work unit" is a
  coherent set of changes that can be completed and delivered before
  context pressure becomes a problem.
- **Don't save the hardest part for last.**<br/>Context quality degrades
  most when you need it most.
- **Watch for warning signs**:<br/>Double-submit needed, compaction
  messages, image upload failures, Claude forgetting earlier decisions.


## 4. Session Handover — The "Know-How Inheritance" Problem

### The core problem
When a session ends, that Claude instance is gone.  A new session
starts with zero shared context.<br/>
There is no "reboot" — only "new hire."

### The CLAUDE.md system (what works)
Maintain versioned handover documents:
- `CLAUDE-v*.md` — what was built, why, key decisions
- `CLAUDE-prompt-eng.md` — this file (operational knowledge)
- `CLAUDE-security-tests.md` — security review state

Feed these to the new Claude at session start with:
*"Read these files first, then let's continue."*

### What to include in handover docs
- Architecture: where things live, why
- Design philosophy: conventions, formatting style, CLI/web parity
- Recent changes: what was just built, what's pending
- Known issues: what failed, what was deferred
- Customer context: who uses this, what they care about
- Build/deploy: how to make tarballs, Dockerfile structure, deploy.sh
- Testing: what to test, how, which test corpus files matter

### What NOT to rely on
- Claude's "memory" feature (settings) — too superficial for project work
- Assuming the new Claude will "remember" — it won't, at all
- Vague references to "what we discussed" — be specific


## 5. Communication Patterns That Work

### BUFFER & DO-IT mode
Chat requestors sometime gives multi-part instructions:
- **BUFFER mode**: "Here are items 1-5, don't act yet"
- **DO-IT mode**: "OK, now execute all of the above"

Claude must respect this.  Don't start coding after item 2 when
there are 3 more items coming.<br/>
Wait for the explicit go-ahead.

### Numbered lists for multi-part requests
When giving Claude 3+ items to address, NUMBER them.<br/>
Claude occasionally drops items from long unnumbered lists.<br/>
Practical limit: ~5 substantive items per request works well.<br/>
More than that, split into two rounds.

### "Show me, don't tell me"
Requestors value working code over explanations.<br/>
Build it, test it, show the test output.<br/>
Don't write paragraphs about what you're going to do — just do it.

### Humor is welcome and functional
Humans should feel free to submit humorous commentary and quips
to Claude as part of the discourse, and you'll get humorous
comments back which can be amusing.  Claude also has a humor
analyzer and synthesizer, which is useful to remind you that a
great amount of human tailoring is built-in to the underlying
inference engine.  These humors seem not to disrupt the
conversation or interfere with the quality of results.

An example of a humorous question — ask Claude to explain this
irony with a straight face:

*We now laugh at Bill Gates's alleged assertion in 1981 that
"640 kilobytes of RAM ought to be enough for anybody."
Today, modern iPhones with only 8 Gigabytes of RAM are considered
low-memory models. But Claude Opus offers customers paid-for chat sessions
with only "200 kilo-tokens" of context window, despite Anthropic's
billion-dollar data centers, with rumors of shopping for nuclear reactors
to get even more electricity than Bitcoin dreamed of, and metaphorically
buying up every RAM chip in sight from around the world.*

A humorous answer could be:<br/>
*"Claude can't answer this question with a straight face,
because Claude doesn't have a face."*

But don't overload Claude with too much humor, else you'll use up
your precious meager context-window budget on this, and then not
have enough left over to get your work done.  Now, none of this is
measurable and there are no dashboard metrics, you'll just have to
"wing it with guesswork" regarding when you might be close to
running out of context-window memory.  Just like Bill Gates had to
do in 1981.  The more things change, the more things stay the same.

### Concise post-delivery commentary
After delivering a tarball, a brief summary of what changed is welcome.<br/>
A 3-paragraph essay about the philosophy behind the changes is not.

### Continuity verification ("security question" pattern)
After session transitions or compactions, the requestor may ask a personal
question ("what's my slogan?") to verify what the new Claude
actually retained vs what it would need to look up.  This is a
legitimate diagnostic — not a trick question.  Answer honestly:
if you found it by searching transcripts rather than having it in
your context, say so.  The gap itself is useful information for
calibrating how much context was lost.

### Effective bug reporting to Claude
Report **symptoms, not diagnoses**.  Show the actual output and say
"this is wrong" rather than "I think the bug is on line 3472."<br/>
This lets Claude find the root cause rather than chasing a potentially
wrong hypothesis.<br/>
Paste real terminal output and screenshots — Claude
can read it, reproduce it internally, and trace the problem.

### Design discussions before implementation
For non-trivial features, discuss the design in conversation before coding.<br/>
The password file format (v2.11.0) went through a full
design conversation — tabs vs whitespace, quoting rules, resolution
order — before a line was written.<br/>
This is faster than iterating through broken implementations.

### Test error paths alongside happy paths
When Claude adds a new code path, ask about failure modes:<br/>
*"What happens with wrong password?  No password?  Missing file?"*

Claude tends to test the happy path and miss error-path regressions.<br/>
Explicit prompting catches these earlier.


## 6. Non-Determinism — Why Two Claudes Give Different Answers

Language models sample from probability distributions — each token
is a weighted random choice.<br/>
Even with identical input, two runs will diverge.<br/>
It's like asking two experienced developers the same
question: both give competent answers, but structure them
differently.

**But results converge.**<br/>
The constraints are deterministic even if
the path isn't.<br/>
Python has one `fnmatch.fnmatch()`.<br/>
PKCS#12 has one binary format.<br/>
Test cases have one correct output.<br/>
Different
phrasings and implementation choices funnel toward the same working
result because the problem constrains the solution space.

Where you see more divergence:<br/>
*design decisions (naming, error
messages, formatting), code organization, variable names.*<br/>
These have genuinely multiple valid answers.  The working code converges;
the aesthetics vary.


## 7. Opus Chat vs Claude Code vs Cowork

**Claude Opus Chat (this web/app interface)**<br/>
This excels at collaborative
design sessions where conversation drives the architecture.  The
tarball handoff is intentionally a review gate — the human tests,
provides feedback as prose, and the loop iterates.  Limitations:
~200K token context window (fills in 8-15 substantive rounds),
per-response output cap (~16-32K tokens — if Claude tries to write
too much in one response, it truncates mid-stream).

**Claude Code**<br/>
This shines when the development environment *is* the
deployment environment — editing files in a repo, running tests
locally, committing directly.  Best for "fix this bug across 15
files" where repo-wide navigation matters more than design
discussion.  Agentic: breaks work into steps naturally, avoiding
the per-response output limit.  Same Opus 4.6 model.

**Cowork** (research preview, Jan 2026+)<br/>
This is Claude Code's agentic
architecture wrapped in the desktop app for non-terminal users.<br/>

Point it at a folder, describe the task, step away.  Key facts:
- **1 million token context window** (5x chat)
- Reads/writes local files directly (no tarball dance)
- Breaks work into subtasks (avoids output generation limit)
- Available on Pro, Max, Team, Enterprise plans
- macOS and Windows
- History stored locally on device (not Anthropic servers)
- "Research preview" — still maturing

**Practical guidance for AI Pair-Programming:**
- Design discussions, architecture decisions, BUFFER mode → Opus Chat
- Large implementation across many files → Claude Code or Cowork
- The tarball workflow is not a limitation per se — it's version
  control through known-good checkpoints that is tested.
  But it IS a workaround for chat's inability to edit files directly.
- If a chat session hits the output generation limit, consider
  switching to Claude Code or Cowork for the implementation phase,
  then returning to chat for review and design iteration.
- When hitting context window limits in chat, the design doc
  approach (CLAUDE-v*.md files) provides continuity that works
  across ALL interfaces — a new Claude Code session can read the
  same design doc that a new chat session would.


## 8. Project-Specific Knowledge

This example applies to project CertGrep.

### Architecture
- `bin/cert-grep.py` — CLI tool, self-contained, ~5400 lines
- `bin/ssl-grep.py` — TLS endpoint scanner, uses cert-grep as library
- `web/app.py` — Flask web application, routes and validation
- `web/cert_web.py` — web decode logic, bridges app.py to cert-grep
- `web/templates/index.html` — single-page app, all HTML/CSS/JS
- `configs/weak.conf` — default weakness policy (broken today)
- `configs/quantum.conf` — quantum migration policy (migrate by 2030)

### Multi-file mode (v2.11.0)
Two-pass strategy when `ver` or `weak` flags are active:
- Pass 1: Load all files (PEM, DER, PKCS#7, PKCS#12, JKS/JCEKS),
  build combined cert list, run ChainVerifier/WeaknessScanner once.
- Pass 2: Display per-file with inline annotations, global numbering.

Password file (`PW=file:<path>` with multi-line file) supports
glob→password mappings and default passwords for batch operations.
See help text for format details.

### Design principles
- CLI and web produce identical output for the same input
- Format auto-detection: user never specifies format, tool figures it out
- Comments use `#` prefix, consistent with PEM/config file conventions
- Symbols: `x` = error, `!` = warning/advisory, `+` = positive/ok
- i18n: 7 languages (en, de, es, fr, it, nl, sv), all in index.html
- Buttons and icons should be language-neutral where possible

### Target customers and anticipated needs
- Individual PKI users, including small-scale techies using or buying X.509 certificates
- Enterprise customers with large certificate estates
- Quantum migration (RSA 2048 → 3072+, EC 256 → 384+) is a
  near-term customer priority with 2030 planning horizon
- "Scalable is Saleable" — features must work for 1 cert and 10,000


## 9. Common Pitfalls

### Audit ALL container types when adding new code paths
`cert-grep.py` handles: x509, pkcs7, pkcs12, jks, key, csr, crl, pubkey.
When adding logic that dispatches on `fmt["type"]`, check every type
in the list.  In v2.11.0, the two-pass multi-file mode was built for
x509/pkcs7/pkcs12 but JKS fell into the "other" bucket silently —
no error, just missing functionality.  A mental checklist prevents this.

### Same logic in cert_grep() and multi-file mode
Single-file processing lives in `cert_grep()`.  Multi-file mode has
its own display logic in `cert_grep_main()`.  When one handles an
error case (bad password, encrypted container), the other must too.
Three separate display bugs in v2.11.0 were caused by multi-file
mode missing error handling that `cert_grep()` already had.

### Path resolution across CLI vs web vs Docker
`__file__`-relative paths resolve differently depending on how
the code is invoked.  Always use explicit paths, never rely on
implicit resolution from `__file__` alone.

### Dockerfile must list every directory
New directories (like `configs/`) must be explicitly added to the
Dockerfile with `COPY configs/ configs/`.  Forgetting this was the
root cause of the v2.8.0 weakness scan failure in web.

### Placeholder text is not a value
HTML `placeholder="configs/weak.conf"` is cosmetic — it's never
sent as form data.  If a default is needed, set `.value` in JS.

### Test corpus naming conventions
Test files encode their password in the filename:
- `jdcc-client-cert.NOPASSWD.p12` — no password
- `jdcc-client-cert.Lame.p12` — password is "Lame"
- `jdcc-client-cert.Cretins-4us.p12` — password is "Cretins-4us"
- `keystore-custom.mypass99.jks` — password is "mypass99"
- `*.changeit.*` — Java default password "changeit"

This makes the test corpus self-documenting.  Password files in
each test directory (`zPasswords.txt`) use this same mapping.

### "Zero rules" vs "nothing / no display"
Always show scan results even when there are zero findings.
Zero is a result.  Silence might be a bug.  This applies to both
weakness scan and chain verification.

### Docker layer caching in Kubernetes deployments
After rebuilding, the old image may still be cached.  Use
`docker build --no-cache` if changes aren't appearing.

### Browser caching
Hard refresh (Cmd+Shift+R / Ctrl+Shift+R) after redeployment.
Old JavaScript can persist despite new server-side code.


## 10. Claude's Self-Awareness Notes

### "Thinking out loud" messages
Claude sometimes produces internal-sounding messages like "oh I see
you have already submitted this."  The "you" in these is Claude
talking to itself, not an implication that the requestor did anything.
These are artifacts of the reasoning process, not accusations.

### Tendency to over-explain
Claude defaults to verbose explanations, but developers may prefer
both concise delivery, and explanations too.  Use this simple
explanation hierarchy: a top-level summary mentioning both the big
picture (if not already known), then allowing (or offering) deep-dive
details when describing things.

### Tendency to guess rather than ask
When Claude encounters ambiguity, it sometimes invents scenarios
(like the `/app/` deployment story) rather than asking.  Better to
say "I'm not sure — can you check X?" than to fabricate a theory.

### Occasional instruction dropping
With 5+ items in a request, Claude may address items 1-3 and
forget 4-5.  But these numbers are just a guess, no one knows
the limits, not even Claude.  This isn't an unforeseen problem
because humans do it too, it's just a reminder for diligence
by those steering the Claude work.

