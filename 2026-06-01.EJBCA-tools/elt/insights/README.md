# ejbca-lifecycle-tool.py — Project Insights

Operational knowledge and documentation for `ejbca-lifecycle-tool.py` (`elt`).<br/>
These documents serve two audiences:

1. **A new Claude instance** — rapid onboarding so the "new hire"
   is productive immediately.
2. **Human developers and reviewers** — reminders of what works, what
   doesn't, and how the project operates.

**Author:** John Buehrer (JohnB),
with AI pair-programming support by Anthropic Claude

---

## Documents

| File | Topic |
|------|-------|
| [CLAUDE-01](CLAUDE-01-ai-coding-terminology.md) | AI-assisted development: terminology and spectrum |
| [CLAUDE-02](CLAUDE-02-prompt-eng.md) | Prompt engineering and session management |
| [CLAUDE-ejbca-checklist.md](CLAUDE-ejbca-checklist.md) | EJBCA configuration checklist for cert-manager integration |
| [CLAUDE-ejbca-fix-requests.md](CLAUDE-ejbca-fix-requests.md) | EJBCA REST API issues and fix requests |
| [CLAUDE-notes-ejbca-lifecycle.md](CLAUDE-notes-ejbca-lifecycle.md) | EJBCA certificate lifecycle findings (full notes) |
| [CLAUDE-notes-ejbca-lifecycle-short.md](CLAUDE-notes-ejbca-lifecycle-short.md) | EJBCA certificate lifecycle findings (summary) |
| [CLAUDE-notes-ejbca-batch-generation.md](CLAUDE-notes-ejbca-batch-generation.md) | EJBCA batch certificate generation notes |
| [CLAUDE-test-cleanup-guide.md](CLAUDE-test-cleanup-guide.md) | Test and cleanup guide |
| [JohnB-ELT-AI-compliance.md](JohnB-ELT-AI-compliance.md) | AI compliance framework notes (corporate PoC guidelines) |

## Releases

| File | Topic |
|------|-------|
| [releases/ELT-release-v3.12.0.md](releases/ELT-release-v3.12.0.md) | v3.12.0 release notes |

---

## Methodology

`ejbca-lifecycle-tool.py` development sits between **AI Pair Programming**
and **AI Agentic Coding**, with explicit session discipline:<br/>
&nbsp; &nbsp; handover docs, version control, and deliberate context management.

Each Claude session gets the latest code from GitLab (source of truth),<br/>
&nbsp; &nbsp; relevant `CLAUDE-*.md` files for project context,<br/>
&nbsp; &nbsp; and a specific work unit scoped to fit within one session.

Session transitions are a shift change, not a failure mode.<br/>
Work products carry forward, even when a chat-session conversation doesn't.

See [CLAUDE-01](CLAUDE-01-ai-coding-terminology.md) for the full
terminology spectrum, and [CLAUDE-02](CLAUDE-02-prompt-eng.md) for
operational details.
