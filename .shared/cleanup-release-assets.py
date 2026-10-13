#!/usr/bin/env python3
"""Delete assets from superseded releases after 14 days; preserve releases and tags."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sys
import subprocess
import threading
import time
import urllib.error
import urllib.request

RETENTION_DAYS = 14


def timestamp(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def release_line(release):
    # Component releases (e.g. shared-v1.2.3) each keep their own current assets.
    match = re.fullmatch(r'(.*?)(?:v)?\d+\.\d+\.\d+(?:[-+].*)?', release['tag_name'])
    return match.group(1) if match else release['tag_name']


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
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
            raise ValueError('invalid repository')
        self.prefix = 'https://api.github.com/repos/' + repository
        self.token = token

    def request(self, path, method='GET'):
        request = urllib.request.Request(self.prefix + path, method=method, headers={
            'Authorization': 'Bearer ' + self.token,
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2026-03-10',
        })
        started = time.monotonic()
        label = f"{method} {path}"
        log(f"{label}: requesting (socket timeout 30s)")
        stop = threading.Event()
        monitor = threading.Thread(target=heartbeat, args=(stop, started, label), daemon=True)
        monitor.start()
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read()
                log(f"{label}: HTTP {response.status} completed in {time.monotonic() - started:.1f}s")
                return json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            log(f"{label}: HTTP {error.code} after {time.monotonic() - started:.1f}s")
            if error.code == 404:
                return None
            raise RuntimeError(f'GitHub {method} {path} failed with status {error.code}') from None
        except Exception as error:
            log(f"{label}: failed ({type(error).__name__}) after {time.monotonic() - started:.1f}s")
            raise
        finally:
            stop.set()
            monitor.join()

    def inventory(self, path):
        result = []
        for page in range(1, 1001):
            data = self.request(f'{path}?per_page=100&page={page}')
            if not isinstance(data, list):
                raise RuntimeError('release inventory unavailable; deletion stopped')
            result.extend(data)
            log(f"Inventory {path} page {page}: {len(data)} entries; {len(result)} total")
            if len(data) < 100:
                return result
        raise RuntimeError('release inventory incomplete; deletion stopped')


def protected_releases(releases, latest, protected_tags):
    protected = {r['id'] for r in releases if r.get('draft') or r.get('immutable') or r['tag_name'] in protected_tags}
    if latest:
        protected.add(latest['id'])
    current = {}
    for release in releases:
        if release.get('draft') or not release.get('published_at'):
            continue
        key = (release_line(release), bool(release.get('prerelease')))
        if key not in current or timestamp(release['published_at']) > timestamp(current[key]['published_at']):
            current[key] = release
    protected.update(r['id'] for r in current.values())
    return protected


def prune(api, now, protected_tags=(), apply=False, confirm=None):
    cutoff = now - timedelta(days=RETENTION_DAYS)
    log(f"Starting release asset cleanup: mode={'APPLY' if apply else 'DRY RUN'}; cutoff={cutoff.isoformat()}")
    releases = api.inventory('/releases')
    latest = api.request('/releases/latest')
    protected = protected_releases(releases, latest, protected_tags)
    log(f"Inventory complete: {len(releases)} releases; {len(protected)} current/protected releases")
    candidates = []
    for release in releases:
        log(f"Checking release {release['id']} tag={json.dumps(release['tag_name'])}")
        if release['id'] in protected or not release.get('published_at') or timestamp(release['published_at']) > cutoff:
            log(f"Keep release {release['id']}: current/protected, unpublished, or younger than 14 days")
            continue
        # Embedded release asset lists may be truncated; paginate every eligible release.
        for asset in api.inventory(f"/releases/{release['id']}/assets"):
            if asset.get('state') == 'uploaded' and timestamp(asset['created_at']) <= cutoff and timestamp(asset['updated_at']) <= cutoff:
                candidates.append((release, asset))
                log(f"Candidate asset {asset['id']} {json.dumps(asset['name'])}; tag={json.dumps(release['tag_name'])}; {asset['size']} bytes")
            else:
                log(f"Keep asset {asset['id']}: recent or not fully uploaded")
    log(f"Candidate review complete: {len(candidates)} assets; {sum(asset['size'] for _, asset in candidates)} bytes eligible")
    plan = {"operation": "delete superseded release assets older than 14 days", "cutoff": cutoff.isoformat(), "items": [{"id": asset["id"], "name": asset["name"], "tag": release["tag_name"], "size_bytes": asset["size"]} for release, asset in candidates], "total_bytes": sum(asset["size"] for _, asset in candidates)}
    if apply and candidates and confirm is not None and not confirm(plan):
        return {"apply": True, "cancelled": True, "retention_days": RETENTION_DAYS, "candidates": len(candidates), "deleted_asset_ids": [], "reclaimed_bytes": 0, "immutable_release_ids": [r["id"] for r in releases if r.get("immutable")]}
    deleted, reclaimed = [], 0
    for index, (release, asset) in enumerate(candidates, 1):
        log(f"Verifying candidate {index}/{len(candidates)}: asset {asset['id']} {json.dumps(asset['name'])}; refreshing current release protection")
        # Refresh current releases before every deletion. A rollback can promote an old release.
        fresh = api.inventory('/releases')
        current_ids = protected_releases(fresh, api.request('/releases/latest'), protected_tags)
        actual_release = next((r for r in fresh if r['id'] == release['id']), None)
        if actual_release is None or release['id'] in current_ids:
            log(f"Keep/skip asset {asset['id']}: release now protected or absent")
            continue
        if any(actual_release.get(key) != release.get(key) for key in ['tag_name', 'published_at', 'draft', 'prerelease']):
            raise RuntimeError('release changed since inventory; deletion stopped')
        path = f"/releases/assets/{asset['id']}"
        actual = api.request(path)
        if actual is None:
            log(f"Skip asset {asset['id']}: already absent")
            continue
        if any(actual.get(key) != asset.get(key) for key in ['id', 'name', 'size', 'created_at', 'updated_at', 'state']):
            raise RuntimeError('release asset changed since inventory; deletion stopped')
        if apply:
            log(f"Deleting asset {asset['id']}; verifying absence next")
            api.request(path, 'DELETE')
            if api.request(path) is not None:
                raise RuntimeError('release asset deletion did not converge')
            deleted.append(asset['id'])
            reclaimed += asset['size']
            log(f"Deleted asset {asset['id']}; reclaimed {reclaimed} bytes so far")
        else:
            log(f"Would delete asset {asset['id']}; {asset['size']} bytes (dry run)")
    log(f"Finished release asset cleanup: candidates={len(candidates)}; deleted={len(deleted)}; reclaimed_bytes={reclaimed}")
    return {'apply': apply, 'retention_days': RETENTION_DAYS, 'candidates': len(candidates), 'deleted_asset_ids': deleted, 'reclaimed_bytes': reclaimed, 'immutable_release_ids': [r['id'] for r in releases if r.get('immutable')]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--yes', action='store_true', help='Confirm the printed deletion plan automatically')
    args = parser.parse_args()
    policy_path = Path('.github/release-asset-retention.json')
    policy = json.loads(policy_path.read_text()) if policy_path.exists() else {'protected_tags': []}
    if set(policy) != {'protected_tags'} or not isinstance(policy['protected_tags'], list) or any(not isinstance(tag, str) or not tag for tag in policy['protected_tags']):
        raise ValueError('release-asset-retention.json must contain a protected_tags string array')
    log(f"Target repository: {os.environ['GITHUB_REPOSITORY']}; explicitly protected tags: {json.dumps(policy['protected_tags'])}")
    result = prune(GitHub(os.environ['GITHUB_REPOSITORY'], resolve_token()), datetime.now(timezone.utc), policy['protected_tags'], args.apply, confirm=lambda plan: confirm_plan(plan, args.yes))
    print(json.dumps(result, sort_keys=True), flush=True)
    if summary := os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(summary, 'a') as output:
            output.write(f"Release assets: {len(result['deleted_asset_ids'])} superseded assets deleted after 14 days; {result['reclaimed_bytes']} bytes reclaimed; {len(result['immutable_release_ids'])} immutable releases preserved.\n")


if __name__ == '__main__':
    main()
