#!/usr/bin/env python3
"""Prune completed-run artifacts older than the enforced five-day ceiling."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
import re
import sys
import subprocess
import threading
import time
import urllib.error
import urllib.request


HEARTBEAT_SECONDS = 10


def log(message):
    print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] {message}", file=sys.stderr, flush=True)


def heartbeat(stop, started, label):
    while not stop.wait(HEARTBEAT_SECONDS):
        log(f"{label}: waiting for GitHub ({time.monotonic() - started:.1f}s elapsed; socket timeout 30s)")


def confirm_plan(plan, auto_confirm=False):
    log("Deletion plan: " + json.dumps(plan, sort_keys=True))
    if auto_confirm:
        log("Confirmation: yes (--yes supplied)")
        return True
    if not sys.stdin.isatty():
        raise RuntimeError("Confirmation requires an interactive terminal; use --apply --yes for automation")
    log("Proceed with this deletion plan? Type yes to confirm [default: no]:")
    try:
        approved = sys.stdin.readline().strip().lower() == "yes"
    except (EOFError, KeyboardInterrupt):
        approved = False
    log("Confirmation: " + ("yes" if approved else "no; cancelled without deleting anything"))
    return approved


def resolve_token():
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        token = os.environ.get(name, "").strip()
        if token:
            log(f"Authentication: {name} environment variable")
            return token
    in_ci = os.environ.get("GITHUB_ACTIONS", "").lower() == "true" or os.environ.get("CI", "").lower() not in ("", "false", "0")
    if in_ci or not sys.stdin.isatty():
        raise RuntimeError("Set GH_TOKEN or GITHUB_TOKEN for automated/noninteractive runs; SSH keys cannot authenticate the GitHub REST API")
    log("Authentication: using existing local GitHub CLI login for github.com")
    try:
        result = subprocess.run(
            ["gh", "auth", "token", "--hostname", "github.com"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("Local GitHub CLI authentication unavailable; sign in to GitHub CLI or set GH_TOKEN. SSH keys alone cannot authenticate the REST API") from None
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError("No usable local GitHub CLI login for github.com; sign in locally or set GH_TOKEN")
    return result.stdout.strip()


class GitHub:
    def __init__(self, repository, token):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("invalid repository")
        self.prefix = "https://api.github.com/repos/" + repository
        self.token = token

    def request(self, path, method="GET"):
        request = urllib.request.Request(self.prefix + path, method=method, headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
        })
        started = time.monotonic()
        label = f"{method} {path}"
        log(f"{label}: requesting (socket timeout 30s)")
        stop = threading.Event()
        monitor = threading.Thread(target=heartbeat, args=(stop, started, label), daemon=True)
        monitor.start()
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                content = response.read()
                log(f"{label}: HTTP {response.status} completed in {time.monotonic() - started:.1f}s")
                return json.loads(content) if content else None
        except urllib.error.HTTPError as error:
            log(f"{label}: HTTP {error.code} after {time.monotonic() - started:.1f}s")
            if error.code == 404:
                return None
            raise RuntimeError(f"GitHub {method} {path} failed with status {error.code}") from None
        except Exception as error:
            log(f"{label}: failed ({type(error).__name__}) after {time.monotonic() - started:.1f}s")
            raise
        finally:
            stop.set()
            monitor.join()

    def artifacts(self):
        result = []
        for page in range(1, 1001):
            data = self.request(f"/actions/artifacts?per_page=100&page={page}")
            if data is None or not isinstance(data.get("artifacts"), list):
                raise RuntimeError("artifact inventory is unavailable or incomplete")
            result.extend(data["artifacts"])
            log(f"Artifact inventory page {page}: {len(data['artifacts'])} artifacts; {len(result)} total")
            if len(data["artifacts"]) < 100:
                return result
        raise RuntimeError("artifact inventory exceeded page limit; no deletion performed")


def prune(api, now, apply=False, confirm=None):
    cutoff = now - timedelta(days=5)
    log(f"Starting Actions cleanup: mode={'APPLY' if apply else 'DRY RUN'}; cutoff={cutoff.isoformat()}")
    candidates = []
    # Finish inventory and validate run states before the first mutation.
    artifacts = api.artifacts()
    log(f"Inventory complete: {len(artifacts)} artifacts; checking source runs")
    for index, item in enumerate(artifacts, 1):
        label = f"artifact {item['id']} {json.dumps(item['name'])}"
        log(f"Checking {index}/{len(artifacts)}: {label}; {item['size_in_bytes']} bytes")
        created = datetime.fromisoformat(item["created_at"].replace("Z", "+00:00"))
        if created > cutoff or item.get("expired"):
            log(f"Keep/skip {label}: recent or already expired")
            continue
        run_id = item.get("workflow_run", {}).get("id")
        if not run_id:
            raise RuntimeError("artifact has no source run; no deletion performed")
        run = api.request(f"/actions/runs/{run_id}")
        if run is not None and run.get("status") == "completed":
            candidates.append(item)
            log(f"Candidate {label}: older than five days; source run completed")
        else:
            log(f"Keep {label}: source run unavailable or not completed")
    log(f"Candidate review complete: {len(candidates)} artifacts; {sum(item['size_in_bytes'] for item in candidates)} bytes eligible")
    plan = {"operation": "delete Actions artifacts older than five days from completed runs", "cutoff": cutoff.isoformat(), "items": [{"id": item["id"], "name": item["name"], "size_bytes": item["size_in_bytes"]} for item in candidates], "total_bytes": sum(item["size_in_bytes"] for item in candidates)}
    if apply and candidates and confirm is not None and not confirm(plan):
        return {"apply": True, "cancelled": True, "candidates": len(candidates), "deleted": 0, "reclaimed_bytes": 0}
    deleted, reclaimed = 0, 0
    for index, item in enumerate(candidates, 1):
        log(f"Verifying candidate {index}/{len(candidates)}: artifact {item['id']} {json.dumps(item['name'])}")
        path = f"/actions/artifacts/{item['id']}"
        actual = api.request(path)
        if actual is None:
            log(f"Skip artifact {item['id']}: already absent")
            continue
        if any(actual.get(key) != item.get(key) for key in ["id", "name", "size_in_bytes", "created_at"]):
            raise RuntimeError("artifact changed since inventory; deletion stopped")
        if apply:
            log(f"Deleting artifact {item['id']}; verifying absence next")
            api.request(path, "DELETE")
            if api.request(path) is not None:
                raise RuntimeError("artifact deletion did not converge")
            deleted += 1
            reclaimed += item["size_in_bytes"]
            log(f"Deleted artifact {item['id']}; reclaimed {reclaimed} bytes so far")
        else:
            log(f"Would delete artifact {item['id']}; {item['size_in_bytes']} bytes (dry run)")
    log(f"Finished Actions cleanup: candidates={len(candidates)}; deleted={deleted}; reclaimed_bytes={reclaimed}")
    return {"apply": apply, "candidates": len(candidates), "deleted": deleted, "reclaimed_bytes": reclaimed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--yes", action="store_true", help="Confirm the printed deletion plan automatically")
    args = parser.parse_args()
    log(f"Target repository: {os.environ['GITHUB_REPOSITORY']}")
    api = GitHub(os.environ["GITHUB_REPOSITORY"], resolve_token())
    result = prune(api, datetime.now(timezone.utc), args.apply, confirm=lambda plan: confirm_plan(plan, args.yes))
    print(json.dumps(result, sort_keys=True), flush=True)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as output:
            output.write(f"Actions retention: {result['deleted']} old artifacts deleted; {result['reclaimed_bytes']} bytes reclaimed.\n")


if __name__ == "__main__":
    main()
