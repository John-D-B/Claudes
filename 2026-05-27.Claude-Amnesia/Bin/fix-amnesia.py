#!/usr/bin/env python3
"""
fix-amnesia.py — Recover Claude Desktop App sidebar entries broken by
the 2.1.144+ "session amnesia" bug.

SYMPTOM
  Clicking a sidebar tile shows "Session not found on disk. Send a
  message to start fresh in this directory." with Archive/Delete buttons,
  even though the conversation jsonl file exists on disk.

CAUSE
  The Desktop App's startup scanner deletes the `cliSessionId` field
  and inserts `transcriptUnavailable: true` into each sidebar entry's
  metadata file at:
    ~/Library/Application Support/Claude/claude-code-sessions/
      <account-uuid>/<workspace-uuid>/local_<uuid>.json

  Without `cliSessionId`, the App has no pointer from the sidebar tile
  to its underlying conversation jsonl in:
    ~/Library/Application Support/Claude/projects/<project-slug>/<uuid>.jsonl

FIX
  For each broken entry, re-set `cliSessionId` and DELETE (not just null)
  the `transcriptUnavailable` key. Auto-discovery: match the local file's
  `createdAt` (unix ms) against the candidate jsonl's first event
  timestamp; closest match within tolerance wins.

  After running with --commit, launch the Desktop App and click each
  fixed sidebar tile ONCE — the conversation loads, and the fix then
  persists across all future launches.

USAGE
  ./fix-amnesia.py                  # dry-run (default)
  ./fix-amnesia.py --commit         # apply fixes
  ./fix-amnesia.py --tolerance 5    # tighten timestamp match (default 60s)
  ./fix-amnesia.py --account UUID   # restrict to one account
  ./fix-amnesia.py --quiet          # only print proposed/applied fixes

IMPORTANT — the App MUST be quit when you run --commit:
  The Desktop App caches local_*.json contents in memory at launch and
  doesn't re-read them. Editing the files while the App is running has
  no effect (and on click, the App will overwrite your edit with its
  stale in-memory state). Always: quit App → run --commit → launch App
  → click each fixed tile.

EXIT CODES
  0   success (no broken entries OR fixes proposed/applied)
  1   error (Desktop App data dir missing, etc.)
  2   no broken entries found, but unmatchable orphans exist (mixed state)
"""

__version__ = "1.2.0"

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

CLAUDE_DATA = Path.home() / "Library/Application Support/Claude"
SESSIONS_DIR = CLAUDE_DATA / "claude-code-sessions"
PROJECTS_DIR = CLAUDE_DATA / "projects"


def slugify_cwd(cwd: str) -> str:
    """Replicate Claude Code's project-slug convention: / and . both become -."""
    return cwd.replace("/", "-").replace(".", "-")


def parse_iso_to_ms(s: str) -> int:
    """Parse ISO8601 string like '2026-05-23T09:33:43.409Z' to unix ms."""
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def find_matching_jsonl(local_data: dict, tolerance_ms: int) -> tuple[str | None, int | None]:
    """Find the jsonl in projects/<slug>/ whose first event timestamp is
    closest to local_data['createdAt']. Returns (uuid, delta_ms) or
    (None, None) if no candidate is within tolerance.
    """
    cwd = local_data.get("cwd")
    target_ms = local_data.get("createdAt")
    if not cwd or not target_ms:
        return None, None

    project_dir = PROJECTS_DIR / slugify_cwd(cwd)
    if not project_dir.is_dir():
        return None, None

    best = None
    best_delta = None
    for jsonl in project_dir.glob("*.jsonl"):
        try:
            # Scan first N lines for the earliest event with a timestamp.
            # Some jsonls start with `ai-title` or similar events that have
            # `timestamp: null`; the real session-start event with a timestamp
            # comes a few lines in.
            ts = None
            with open(jsonl, "r") as f:
                for _ in range(20):
                    line = f.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    candidate = event.get("timestamp")
                    if candidate:
                        ts = candidate
                        break
            if not ts:
                continue
            jsonl_ms = parse_iso_to_ms(ts)
            delta = abs(jsonl_ms - target_ms)
            if best_delta is None or delta < best_delta:
                best = jsonl.stem
                best_delta = delta
        except (OSError, ValueError):
            continue

    if best_delta is not None and best_delta <= tolerance_ms:
        return best, best_delta
    return best, best_delta  # return best-effort even if over tolerance, caller decides


def main() -> int:
    p = argparse.ArgumentParser(
        description="Fix Claude Desktop App session-amnesia (post-2.1.144 update).",
        epilog="After --commit, launch the App and click each fixed tile once to lock in.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--commit", action="store_true",
                   help="Apply fixes. Without this flag, runs in dry-run mode.")
    p.add_argument("--tolerance", type=int, default=60,
                   help="Max seconds between local file's createdAt and jsonl's "
                        "first-event timestamp for a match to be accepted (default: 60).")
    p.add_argument("--account", default="*",
                   help="Restrict to single account UUID (default: all).")
    p.add_argument("--workspace", default="*",
                   help="Restrict to single workspace UUID (default: all).")
    p.add_argument("--quiet", action="store_true",
                   help="Only print fix lines; suppress headers and summary.")
    args = p.parse_args()

    if not SESSIONS_DIR.is_dir():
        print(f"ERROR: {SESSIONS_DIR} not found. Is Desktop App installed?", file=sys.stderr)
        return 1

    pattern = f"{args.account}/{args.workspace}/local_*.json"
    paths = sorted(SESSIONS_DIR.glob(pattern))
    if not paths:
        print(f"No local_*.json files matched {pattern}", file=sys.stderr)
        print()
        return 0

    if not args.quiet:
        print(f"Mode:       {'COMMIT' if args.commit else 'DRY-RUN'}")
        print(f"Tolerance:  {args.tolerance}s")
        print(f"Scanned:    {len(paths)} sidebar entries")
        print()

    broken = []
    for path in paths:
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as e:
            print(f"  SKIP unreadable {path}: {e}", file=sys.stderr)
            continue
        # Amnesia signature: transcriptUnavailable key present AND truthy.
        # Healthy entries either lack the key entirely or have it null/false.
        if not data.get("transcriptUnavailable"):
            continue
        broken.append((path, data))

    if not broken:
        if not args.quiet:
            print("No amnesia'd entries found. Sidebar is healthy.")
            print()
        return 0

    if not args.quiet:
        print(f"Found {len(broken)} amnesia'd entries:")
        print()

    fixed = 0
    skipped = 0
    tolerance_ms = args.tolerance * 1000
    for path, data in broken:
        title = data.get("title", "(no title)")
        cwd = data.get("cwd", "(no cwd)")
        match_uuid, delta_ms = find_matching_jsonl(data, tolerance_ms)

        if not match_uuid or (delta_ms is not None and delta_ms > tolerance_ms):
            delta_str = f"closest delta {delta_ms / 1000:.1f}s" if delta_ms else "no candidate"
            print(f"  {title}")
            print(f"    file: {path.name}")
            print(f"    cwd:  {cwd}")
            print(f"    NO MATCH ({delta_str}, tolerance {args.tolerance}s). Skipping.")
            print()
            skipped += 1
            continue

        delta_s = (delta_ms or 0) / 1000.0
        print(f"  {title}")
        print(f"    file:         {path.name}")
        print(f"    cwd:          {cwd}")
        print(f"    cliSessionId: {match_uuid}")
        print(f"    delta:        {delta_s:.3f}s")

        if args.commit:
            backup = path.with_name(f"{path.name}.bak-fixamnesia.{int(time.time())}")
            path.rename(backup)
            data["cliSessionId"] = match_uuid
            data.pop("transcriptUnavailable", None)
            backup.read_text()  # sanity check that backup is readable
            path.write_text(json.dumps(data, indent=2))
            print(f"    APPLIED (backup: {backup.name})")
            fixed += 1
        else:
            print(f"    DRY-RUN")
        print()

    if not args.quiet:
        if args.commit:
            print(f"Done. Fixed {fixed}, skipped {skipped}.")
            if fixed > 0:
                print()
                print("NEXT STEPS:")
                print("  1. Launch the Claude Desktop App.")
                print("  2. Click each fixed sidebar tile ONCE — verify the conversation loads.")
                print("     This 'locks in' the fix; the App will preserve cliSessionId across")
                print("     all future launches.")
                print("  3. Skipped entries (no jsonl match) may require manual mapping; check")
                print("     `projects/<slug>/` to see if the jsonl was deleted or moved.")
                print()
        else:
            print(f"Dry-run complete. {len(broken) - skipped} would be fixed, "
                  f"{skipped} unmatchable. Re-run with --commit to apply.")
            print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
