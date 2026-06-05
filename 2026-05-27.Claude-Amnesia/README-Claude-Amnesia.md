# Claude Desktop App — "Session Amnesia" Diagnosis and Fix

**Author:**  JohnB, with AI pair-programming support by Anthropic Claude<br/>
**Diagnosed:** 2026-05-28: Claude Code "TwoSter" (Opus 4.7) + JohnB collaboration.<br/>
**Affected versions:** Claude Desktop App 2.1.144+ (macOS).<br/>
**Status:** root cause identified, file-level workaround proven, auto-recovery script: `fix-amnesia.py`

## TL;DR

After a Claude Desktop App update around late May 2026, every previously-existing
sidebar session tile shows **"Session not found on disk"** when clicked, even
though the conversation jsonl files are still intact on disk. CLI sessions
(`claude --resume`) still work fine — only the Desktop App's sidebar→jsonl
link is broken.

**Root cause:**<br/>
The App's startup scanner deletes the `cliSessionId` field from
each sidebar entry's metadata file and replaces it with a `transcriptUnavailable:
true` sentinel. The deletion happens unconditionally on every launch (even for
sessions created seconds earlier), so without intervention the App can never
resume a session across a quit/relaunch.

**Fix:**<br/>
For each broken entry, restore `cliSessionId` and DELETE (not just null)
the `transcriptUnavailable` key. After re-launching the App and clicking each
fixed tile once, the conversation loads. The entry *usually* persists across
future launches — but not reliably (see "Caveat: trust is not permanent"
below). Auto-discovery + repair is automated in `Bin/fix-amnesia.py`, so the
fix can be re-applied any time amnesia recurs.

**Critical workflow constraint:**<br/>
The App MUST be quit when the fix is applied.
The App caches `local_*.json` contents in memory at launch and doesn't re-read
them. Edit while the App is running and your edit will be ignored (or worse,
overwritten with the App's stale broken state on click). The reliable
sequence is: **quit App → run fix → launch App → click each tile.**

**Caveat: trust is not permanent.**<br/>
The App's startup scanner nullifies most broken entries on every launch, but
the heuristic isn't fully deterministic. We observed entries that were
clicked-and-loaded successfully in one launch being re-nullified by the
scanner on a subsequent launch. Other entries from the same recovery batch
stay healthy across many launches. We do not yet know what differentiates
"trusted" entries from re-nullified ones — order-of-click, time-since-load,
amount of in-session activity, and per-launch RNG are all candidates we
haven't ruled out. Pragmatic implication: keep `Bin/fix-amnesia.py` handy
and re-run it any time amnesia recurs. The script is idempotent and reports
"Sidebar is healthy" when there's nothing to do, so a re-run after every
Desktop App update (or on demand whenever you see "Session not found") is
the safe default.

## Symptom

Click a sidebar tile in Claude Desktop App → main pane shows:

```
Session not found on disk
Send a message to start fresh in this directory.
[Archive]  [Delete]
```

The title bar correctly shows the project + session name (so the App knows
*which* session you wanted), but it can't load the conversation.

Verifying the data isn't actually gone:

```
ls "$HOME/Library/Application Support/Claude/projects/<project-slug>/"
```

…will show the jsonl files, intact, properly sized. CLI resume works:

```
claude --resume <jsonl-uuid>
```

…and the conversation is there. The brokenness is purely in the Desktop App's
state.

## Architecture (as we reverse-engineered it)

Sidebar tiles are described by per-session JSON files at:

```
~/Library/Application Support/Claude/claude-code-sessions/
  <account-uuid>/<workspace-uuid>/local_<sidebar-uuid>.json
```

Each file has a `sessionId` (the Desktop-internal `local_<uuid>` matching the
filename) and — when healthy — a `cliSessionId` pointing at the conversation's
underlying jsonl UUID. The jsonl lives at:

```
~/Library/Application Support/Claude/projects/<project-slug>/<jsonl-uuid>.jsonl
```

…where `<project-slug>` is the project's `cwd` with `/` and `.` both replaced
by `-`. So the chain to load a conversation is:

&nbsp; &nbsp; **sidebar tile** → `local_<uuid>.json` → `cliSessionId` →
&nbsp; &nbsp; `projects/<slug>/<cliSessionId>.jsonl` → conversation events

Break the `cliSessionId` link and the App has no way to find the conversation
even though the file is right there on disk.

**Broken entry** (after scanner runs on launch):

```json
{
  "sessionId": "local_a1b2c3d4-...",
  "title": "EJBCA-ce TwoSter",
  "cwd": "/Users/jdb/work.Claude/2026-05-19.EJBCA-ce",
  "createdAt": 1748939630700,
  "transcriptUnavailable": true
}
```

**Healthy entry** (as originally written, or after fix applied):

```json
{
  "sessionId": "local_a1b2c3d4-...",
  "title": "EJBCA-ce TwoSter",
  "cwd": "/Users/jdb/work.Claude/2026-05-19.EJBCA-ce",
  "createdAt": 1748939630700,
  "cliSessionId": "4b6270cb-21cf-4edb-9449-48ea842cc378"
}
```

The difference is two fields: `transcriptUnavailable` is present (broken) vs.
absent (healthy), and `cliSessionId` is absent (broken) vs. set to the
matching jsonl UUID (healthy).

## Root cause

On startup, the Desktop App scans every `local_*.json` file. For reasons we
didn't fully reverse-engineer (possibly related to the new `sidebarMode:
"epitaxy"` introduced in 2.1.144+, possibly schema migration that fails
silently), the scanner:

1. **Deletes the `cliSessionId` key** entirely from the file (not nulled —
&nbsp; &nbsp; removed from the JSON object's key set).
2. **Inserts `transcriptUnavailable: true`** as a sentinel.

This happens on EVERY launch, to EVERY entry, regardless of how recently the
session was created. We confirmed this by creating FreshSter sessions in
Desktop, quitting, relaunching, and watching the App null out cliSessionId on
sessions born minutes earlier.

The `cliSessionId` mapping does not live in any other Claude data file. We
grep'd both LevelDB stores (`Local Storage/leveldb/`, `IndexedDB/.../leveldb/`)
and found the sidebar `local_<uuid>` IDs present but no jsonl UUIDs anywhere
in the LevelDB. So the App's startup scanner has nowhere to repopulate
cliSessionId from. The field is one-shot at session-creation time, and the
scanner clobbers it on every restart.

## The fix recipe

**Crucial detail:** the scanner appears to treat presence of
`transcriptUnavailable` (irrespective of value) as the "this entry is broken,
clear cliSessionId" marker. Setting it to `false` is not enough — the key must
be **removed**. Once the key is absent AND cliSessionId is valid, the scanner
leaves the entry alone.

Manual fix for one entry:

```bash
F="$HOME/Library/Application Support/Claude/claude-code-sessions/<acct>/<ws>/local_<uuid>.json"
JSONL_UUID="<the-real-jsonl-uuid>"
cp "$F" "$F.bak.$(date +%s)"
jq --arg u "$JSONL_UUID" \
   'del(.transcriptUnavailable) | .cliSessionId = $u' "$F" > "$F.new" \
   && mv "$F.new" "$F"
```

Then launch the Desktop App and click the tile. The conversation loads.
After this initial load, the App accepts the entry as valid and never re-nulls
it on subsequent launches.

**Finding the right `JSONL_UUID`:** the only reliable signal is timestamp
proximity. The local file's `createdAt` (unix ms) should match the
corresponding jsonl's first event `timestamp` (ISO8601 string) within a few
seconds. Older formats may not be precise to ms; allow tolerance of a minute
or so.

## Auto-recovery: `Bin/fix-amnesia.py`

The recovery script automates the discovery and fix for any number of broken
sidebar entries, across any/all accounts and workspaces.

**Usage:**

```bash
# Dry-run (default): report what would be fixed
./Bin/fix-amnesia.py

# Apply fixes
./Bin/fix-amnesia.py --commit

# Narrow scope
./Bin/fix-amnesia.py --account <account-uuid> --workspace <workspace-uuid>

# Tighten timestamp tolerance (default 60s)
./Bin/fix-amnesia.py --tolerance 5
```

**What it does:**

1. Enumerates every `local_*.json` under `claude-code-sessions/<acct>/<ws>/`.
2. Marks an entry "broken" if `transcriptUnavailable` is truthy.
3. For each broken entry, slugifies the entry's `cwd` field, scans
&nbsp; &nbsp; `projects/<slug>/*.jsonl`, reads each jsonl's first event
&nbsp; &nbsp; timestamp, and picks the one closest to the entry's `createdAt`.
4. Rejects matches outside the tolerance window (no match shown for
&nbsp; &nbsp; ambiguous cases — safer to skip than to mislink).
5. With `--commit`, writes a `.bak-fixamnesia.<ts>` backup, then rewrites the
&nbsp; &nbsp; local file with `cliSessionId` set and `transcriptUnavailable`
&nbsp; &nbsp; deleted.

**Post-fix step (manual):**<br/>
Launch the Desktop App and click each fixed tile
ONCE. The conversation loads, the App marks the entry as valid in its
in-memory state, and subsequent launches USUALLY leave it alone — though
not always (see "Caveat: trust is not permanent" in the TL;DR). If amnesia
recurs on a later launch, just re-run the script.

**Pre-fix step (mandatory):**<br/>
The App MUST be quit before running with
`--commit`. Verify with `pgrep -fl "Claude.app"` — it should return nothing.
The App caches per-tile metadata in memory at launch; edits made while the
App is running are silently ignored at best, or written-back-stale on click
at worst (the latter is how we learned this rule the hard way).

**Re-run-anytime:**<br/>
The script is idempotent. Re-running with no broken
entries reports "Sidebar is healthy" and exits 0. Run it any time the App's
sidebar starts showing amnesia.

## Bug report (for Anthropic)

Suggested text for reporting this upstream:

> **Title:** Desktop App 2.1.144+ — session persistence broken across all
> restarts; sidebar tiles show "Session not found on disk"
>
> **Versions affected:** Desktop App 2.1.144 (macOS); first noticed after
> the late-May 2026 update.
>
> **Symptom:** Every previously-working sidebar session tile, AND every
> session created during the current launch, shows "Session not found on
> disk" when clicked after the App is quit and relaunched. Underlying
> conversation jsonl files in `~/Library/Application Support/Claude/projects/`
> are intact (`claude --resume <uuid>` works via CLI).
>
> **Root cause (confirmed):** the startup scanner deletes the `cliSessionId`
> field from each `claude-code-sessions/.../local_<uuid>.json` and inserts
> `transcriptUnavailable: true`. No other persisted store holds the
> sidebar→jsonl link, so the App has nowhere to recover it from. We grep'd
> Local Storage and IndexedDB LevelDB stores for jsonl UUIDs and found none.
>
> **Reproduction (100%):**
> 1. Create a new session in Desktop App (any project).
> 2. Have a couple of conversation turns.
> 3. Quit the App.
> 4. Relaunch.
> 5. Click the just-created sidebar tile → "Session not found on disk."
>
> **User-side workaround:** Manually re-set `cliSessionId` and DELETE the
> `transcriptUnavailable` key in the local file, then launch App and click
> the tile once. Conversation loads; entry usually persists across launches
> but the scanner's trust heuristic is not fully deterministic — entries can
> be re-nullified on a later launch with no user intervention, requiring
> the workaround to be re-applied. Auto-recovery script:
> <https://github.com/John-D-B/Claudes/blob/main/2026-05-27.Claude-Amnesia/Bin/fix-amnesia.py>
>
> **Impact:** Multi-session workflows in Desktop App are broken — every
> restart can wipe session continuity for an unpredictable subset of tiles.
> The only fully-intact path is CLI resume.

## Discovery timeline (how we got here)

For posterity / debugging similar issues in the future, here's the path
from symptom to root cause:

**Step 1 — confirm data isn't lost.**<br/>
`ls` on `projects/<slug>/` showed all
jsonls intact, sized normally, mtimes recent. CLI `claude --resume` worked.
So the brokenness is in the App, not the data.

**Step 2 — find the sidebar's source of truth.**<br/>
The Desktop App's
`claude_desktop_config.json` showed a new `sidebarMode: "epitaxy"` with empty
`epitaxyPrefs.dframe-local-slice.pinnedOrder` — flagged as suspect but turned
out to be a separate (and orthogonal) state. The real per-tile metadata lives
in `claude-code-sessions/<acct>/<ws>/local_<uuid>.json`.

**Step 3 — inspect a working vs. broken entry.**<br/>
Broken entries had
`cliSessionId: null` (actually, key absent) AND `transcriptUnavailable: true`.
Healthy entries had `cliSessionId` set to a valid jsonl UUID and no
`transcriptUnavailable` key. The schema was otherwise identical.

**Step 4 — first attempted fix (failed).**<br/>
Set `cliSessionId` to the right
UUID, set `transcriptUnavailable: false`. App relaunch nullified the edit and
re-set `transcriptUnavailable: true`. So the App actively rejects our value.

**Step 5 — create known-good comparisons.**<br/>
Spawned FourSter and FiveSter via
the Desktop App (new sessions, naturally well-formed). Captured the
file-system delta with `find -newer`. New `local_*.json` files had
`cliSessionId` set and no `transcriptUnavailable` key. Clean reference.

**Step 6 — discover the scanner is universal.**<br/>
Quit App, relaunch. FourSter
and FiveSter — both born minutes earlier — were ALSO amnesia'd. So the scanner
doesn't distinguish old from new. Every session is at risk.

**Step 7 — refine the fix.**<br/>
Critical insight: my first attempt set
`transcriptUnavailable: false`. The second attempt **DELETED** the key
entirely. With key absent + cliSessionId set, the scanner accepted the entry.
Conversation loaded.

**Step 8 — test whether a live PID is needed.**<br/>
I (TwoSter, CLI session)
had a live process owning my own jsonl. ThreeSter (no live process) was
edited the same way — App accepted it too. So live PID is NOT required;
file state alone is sufficient.

**Step 9 — verify persistence (initial check).**<br/>
After clicking the fixed tile in the App
and quitting, re-read the file: cliSessionId still set, no
`transcriptUnavailable` key. Initial conclusion was that the fix is one-shot:
apply once, click once, done.

**Step 10 — discover that "trust" is unreliable.**<br/>
On a later App launch (same workday), some entries that had been
clicked-and-loaded successfully were re-nullified by the scanner anyway,
while other entries from the same recovery batch stayed healthy. The
"trust" mechanism is not deterministic. Re-applying the script + click-load
cycle restored them. So the workflow is: keep the script handy, re-run as
needed; the fix is not guaranteed-permanent, but it's cheap to re-apply.

## Reference: key file locations

| Path | Purpose |
|---|---|
| `~/Library/Application Support/Claude/claude-code-sessions/<acct>/<ws>/local_<uuid>.json` | Per-tile sidebar metadata (THIS is what the bug breaks). |
| `~/Library/Application Support/Claude/projects/<slug>/<uuid>.jsonl` | Conversation event log (the actual transcript). |
| `~/Library/Application Support/Claude/.claude.json` | CLI per-project state (lastSessionId, allowedTools). Not relevant to amnesia. |
| `~/Library/Application Support/Claude/claude_desktop_config.json` | Desktop App config (MCP servers, sidebarMode). Not the source of amnesia. |
| `~/Library/Application Support/Claude/sessions/<pid>.json` | Live per-PID process registry. Ephemeral; deleted on subprocess exit. |
| `~/Library/Application Support/Claude/Local Storage/leveldb/` | Electron localStorage. Holds sidebar UUIDs but NOT cliSessionId mappings. |
| `~/Library/Application Support/Claude/IndexedDB/https_claude.ai_0.indexeddb.leveldb/` | App's IndexedDB. Holds editor state, not session metadata. |
| `~/Library/Application Support/Claude/backups/.claude.json.backup.<ts>` | Periodic backups of the CLI state file. Not session backups. |

## Open questions

These remain unresolved at writeup time and would benefit from clarification
from Anthropic or further reverse-engineering:

**Why does the scanner null cliSessionId in the first place?**<br/>
Best guess is
a schema-migration step that was supposed to derive cliSessionId from some
new persistent store (LevelDB? cloud sync?) that isn't yet populated.
Migration assumes derivation works; it doesn't; cliSessionId is left null.

**Why does clicking the tile partially "lock in" the fix?**<br/>
After a successful
conversation load, the App USUALLY stops re-nullifying cliSessionId on
subsequent launches — but not reliably (see Step 10 above). Some in-memory
or persistent flag presumably changes on successful load, but the scanner's
condition for "should I nullify this entry?" isn't a pure function of that
flag. Possibilities: per-launch RNG, click-order, time-since-load, amount
of conversation activity, or interaction with App state we haven't
identified. Reverse-engineering this would yield either a fully-automated
fix or at least a predictable workflow; right now, the safe assumption is
"re-run the script whenever amnesia recurs."

**Are the "epitaxy" sidebar-mode bits related?**<br/>
`claude_desktop_config.json`
shows `sidebarMode: "epitaxy"` with empty `epitaxyPrefs` collections. We
left them alone and the workaround still works, so they're either irrelevant
to amnesia or a separate (orthogonal) regression.

**Is this fixed in newer Desktop App versions?**<br/>
Unknown — diagnosed against 2.1.144. Re-test on update.
