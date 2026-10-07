#!/usr/bin/env python3
"""Publish piddigger's Debian packages to the THUGS(red) APT archive.

Maintainer tooling for apt.thugs.red (XXC-APTD publishing API), suite zerotrust.

  apt-repo.py status    the token reaches the suite; what is currently staged
  apt-repo.py publish   upload, stage, review and publish dist/*.deb, then verify
  apt-repo.py verify    check the public archive serves exactly dist/*.deb
                        (reads no credentials, makes no management API calls)

Credentials live outside the checkout in an account-owned 0600 TOML file inside
a 0700 directory:

  api_base  = "https://<operator-supplied host>/api/v1"
  suite     = "zerotrust"
  api_token = "xxc_aptd_..."
  # allow_private_http = true   only for a numeric RFC 1918 IPv4 endpoint

It is read from $PIDDIGGER_APT_CONFIG, else $XDG_CONFIG_HOME/xxc-aptd/piddigger.toml,
else the shared THUGS(red) project token in $XDG_CONFIG_HOME/xxc-aptd/nulllobby.toml.

Publishing never removes, downgrades or replaces anything: a staged selection
containing anything other than this release's packages stops it, and a
published version with different bytes is a conflict, not an overwrite.
"""
import email.utils
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = "piddigger"
ARCHIVE = "https://apt.thugs.red/repo"
SUITE = "zerotrust"
KEYRING = ROOT / "packaging" / "thugsred-archive-keyring.gpg"
KEY_SHA256 = "026dd9704f4c3c51dc060e39d2834e81d21bf25f71e6ac943061ac2b4c2c1019"
KEY_FINGERPRINT = "FAE8475A738BE7656B2550A421A7B0A5B3579EE0"
MAX_JSON = 1 << 20
MAX_INDEX = 8 << 20
MAX_DEB = 64 << 20
FIELDS = ("name", "version", "architecture", "sha256", "size", "component")
INDEX = {}  # architecture -> parsed signed Packages index


class Fail(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_bounded(path, limit):
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise Fail(f"{path} must be a regular file; symlinks rejected")
        with open(path, "rb") as f:
            data = f.read(limit + 1)
    except OSError:
        raise Fail(f"cannot read {path}") from None
    if len(data) > limit:
        raise Fail(f"{path} exceeds its size limit")
    return data


# --- configuration ------------------------------------------------------------


def config_path():
    if env := os.environ.get("PIDDIGGER_APT_CONFIG"):
        return Path(env)
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "xxc-aptd"
    for name in ("piddigger.toml", "nulllobby.toml"):
        if os.path.lexists(base / name):
            return base / name
    raise Fail(f"no APT credentials: create {base / 'piddigger.toml'} or set PIDDIGGER_APT_CONFIG")


def private_ipv4(host):
    try:
        ip = ipaddress.IPv4Address(host or "")
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def load_config():
    path = config_path()
    try:
        if path.resolve().is_relative_to(ROOT):
            raise Fail("APT credentials must live outside the repository")
        f, d = os.lstat(path), os.lstat(path.parent)
    except OSError:
        raise Fail("APT configuration unavailable") from None
    uid = os.geteuid()
    if (
        not stat.S_ISREG(f.st_mode)
        or not stat.S_ISDIR(d.st_mode)
        or f.st_uid != uid
        or d.st_uid != uid
        or f.st_mode & 0o077
        or d.st_mode & 0o077
    ):
        raise Fail("APT config must be an account-owned 0600 file in a 0700 directory; symlinks rejected")
    try:
        doc = tomllib.loads(read_bounded(path, 16 * 1024).decode())
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise Fail("invalid APT configuration") from None
    if set(doc) - {"api_base", "suite", "api_token", "allow_private_http"} or doc.get("suite") != SUITE:
        raise Fail("APT configuration must select the zerotrust suite and only supported fields")
    api = urllib.parse.urlsplit(str(doc.get("api_base", "")))
    private_http = doc.get("allow_private_http") is True and api.scheme == "http" and private_ipv4(api.hostname)
    if (
        (api.scheme != "https" and not private_http)
        or not api.hostname
        or api.username
        or api.password
        or api.query
        or api.fragment
        or not api.path.endswith("/api/v1")
    ):
        raise Fail(
            "APT API base must be HTTPS (or opted-in private IPv4 HTTP) ending in /api/v1, "
            "without credentials, query or fragment"
        )
    token = doc.get("api_token")
    if not isinstance(token, str) or not 32 <= len(token) <= 256 or not re.fullmatch(r"xxc_aptd_\w+", token, re.ASCII):
        raise Fail("invalid APT credential format")
    return api.geturl(), token


# --- HTTP ---------------------------------------------------------------------


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


# No environment proxies and no redirects: the bearer token only ever goes to api_base.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


def fetch(url, limit, label, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "piddigger-release-tool", **(headers or {})})
    try:
        with OPENER.open(req, timeout=60) as resp:
            body = resp.read(limit + 1)
    except urllib.error.HTTPError as e:
        raise Fail(f"HTTP {e.code} for {label}; response details withheld") from None
    except (urllib.error.URLError, OSError):
        raise Fail(f"request for {label} failed; inspect status before retrying") from None
    if len(body) > limit:
        raise Fail(f"response for {label} is too large")
    return body


class Api:
    def __init__(self, base, token):
        self.base = base
        self.auth = f"Bearer {token}"

    def call(self, path, body=None, kind="application/json"):
        headers = {"Authorization": self.auth}
        if body is not None:
            headers["Content-Type"] = kind
        raw = fetch(f"{self.base}{path}?suite={SUITE}", MAX_JSON, path, body, headers)
        try:
            value = json.loads(raw)
        except ValueError:
            raise Fail(f"invalid JSON from {path}") from None
        if not isinstance(value, dict):
            raise Fail(f"unexpected response from {path}")
        return value


def items(obj, key):
    value = obj.get(key)
    if not isinstance(value, list):
        raise Fail(f"APT response is missing '{key}'")
    return value


def uuid(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", value, re.I):
        raise Fail("invalid APT object ID")
    return value


def check_suite(api):
    if SUITE not in items(api.call("/suites"), "suites"):
        raise Fail("the APT token cannot access zerotrust")


# --- local packages -----------------------------------------------------------


def artifacts():
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    debs = sorted((ROOT / "dist").glob(f"{NAME}_{version}_*.deb"))
    if not debs:
        raise Fail(f"no dist/{NAME}_{version}_*.deb — run `make deb-bookworm` (or `make deb`) first")
    out = []
    for path in debs:
        data = read_bounded(path, MAX_DEB)
        arch = path.stem.rsplit("_", 1)[1]
        meta = subprocess.run(
            ["dpkg-deb", "--show", "--showformat=${Package}\n${Version}\n${Architecture}", path],
            capture_output=True,
            text=True,
        )
        if meta.returncode != 0 or meta.stdout != f"{NAME}\n{version}\n{arch}":
            raise Fail(f"{path.name}: package metadata does not match its file name")
        out.append({
            "name": NAME, "version": version, "architecture": arch, "sha256": sha256(data),
            "size": len(data), "component": "main", "file": path.name, "bytes": data,
        })
    return out


def matches(a, entry):
    return all(entry.get(k) == a[k] for k in FIELDS)


# --- public archive -----------------------------------------------------------


def signed_by_archive_key(status):
    lines = [line.split() for line in status.splitlines()]
    if any(f[1:2] in (["BADSIG"], ["ERRSIG"], ["EXPKEYSIG"], ["REVKEYSIG"], ["EXPSIG"]) for f in lines):
        return False
    # VALIDSIG <fpr> <date> <ts> <expire> <ver> <reserved> <pubkey-algo> <hash-algo> <class> <primary-fpr>
    return any(
        f[:2] == ["[GNUPG:]", "VALIDSIG"] and len(f) == 12 and f[11] == KEY_FINGERPRINT and f[8] == "22" and f[9] == "8"
        for f in lines
    )


def release_time(fields, key):
    try:
        return email.utils.parsedate_to_datetime(fields[key]).timestamp()
    except (KeyError, TypeError, ValueError):
        raise Fail(f"signed Release has no valid {key}") from None


def public_index(arch):
    if arch in INDEX:
        return INDEX[arch]
    key = read_bounded(KEYRING, 64 * 1024)
    if sha256(key) != KEY_SHA256:
        raise Fail("archive keyring differs from its pinned SHA-256")
    release = fetch(f"{ARCHIVE}/dists/{SUITE}/Release", MAX_JSON, "Release")
    signature = fetch(f"{ARCHIVE}/dists/{SUITE}/Release.gpg", 64 * 1024, "Release.gpg")
    with tempfile.TemporaryDirectory(prefix="piddigger-apt-") as tmp:
        t = Path(tmp)
        for name, data in (("keyring.gpg", key), ("Release", release), ("Release.gpg", signature)):
            (t / name).write_bytes(data)
        gpgv = subprocess.run(
            ["timeout", "--signal=KILL", "30s", "gpgv", "--homedir", tmp, "--keyring", t / "keyring.gpg",
             "--status-fd", "1", t / "Release.gpg", t / "Release"],
            capture_output=True,
            text=True,
        )
    if gpgv.returncode != 0 or not signed_by_archive_key(gpgv.stdout):
        raise Fail("Release.gpg is not a valid Ed25519/SHA-256 signature from the pinned archive key")

    text = release.decode()
    head, _, sums = text.partition("\nSHA256:\n")
    fields = dict(line.split(": ", 1) for line in head.splitlines() if ": " in line and not line.startswith(" "))
    now = time.time()
    if fields.get("Suite") != SUITE:
        raise Fail("signed Release is for the wrong suite")
    if release_time(fields, "Date") > now + 600 or release_time(fields, "Valid-Until") <= now:
        raise Fail("APT metadata is expired or dated in the future")
    want = f"main/binary-{arch}/Packages"
    entries = []
    for line in sums.splitlines():
        if not line.startswith(" "):
            break
        f = line.split()
        if len(f) == 3 and f[2] == want:
            entries.append(f)
    if len(entries) != 1 or not re.fullmatch(r"[0-9a-f]{64}", entries[0][0]) or not entries[0][1].isdigit():
        raise Fail(f"signed Release has no single {want} entry")
    digest, size = entries[0][0], int(entries[0][1])
    if size > MAX_INDEX:
        raise Fail(f"{want} is too large")
    # Acquire by hash so the index matches exactly the signed generation.
    index = fetch(f"{ARCHIVE}/dists/{SUITE}/main/binary-{arch}/by-hash/SHA256/{digest}", MAX_INDEX, want)
    if len(index) != size or sha256(index) != digest:
        raise Fail(f"{want} differs from the signed Release")
    INDEX[arch] = parse_index(index.decode())
    return INDEX[arch]


def parse_index(text):
    names = {"Package": "name", "Version": "version", "Architecture": "architecture",
             "SHA256": "sha256", "Size": "size", "Filename": "filename"}
    out = []
    for stanza in filter(str.strip, text.split("\n\n")):
        item = {"component": "main"}
        for line in stanza.splitlines():
            if line.startswith((" ", "\t")):
                continue
            key, sep, value = line.partition(": ")
            if not sep:
                raise Fail("invalid APT index field")
            if key in names:
                if names[key] in item:
                    raise Fail("duplicate APT index field")
                if key == "Size" and not value.isdigit():
                    raise Fail("invalid package size in APT index")
                item[names[key]] = int(value) if key == "Size" else value
        out.append(item)
    return out


def published(index, a):
    same = [p for p in index if (p.get("name"), p.get("version"), p.get("architecture")) == (a["name"], a["version"], a["architecture"])]
    if not same:
        return None
    if len(same) == 1 and matches(a, same[0]):
        return same[0]
    raise Fail(f"{a['file']}: this version is already published with different bytes; bump the version")


def pool_path(path):
    if (
        not isinstance(path, str)
        or not path.startswith("pool/main/")
        or not path.endswith(".deb")
        or len(path) > 512
        or any(s in ("", ".", "..") for s in path.split("/"))
        or not re.fullmatch(r"[A-Za-z0-9/._+-]+", path)
    ):
        raise Fail("invalid public APT package path")
    return path


# --- commands -----------------------------------------------------------------


def review(diff, allowed):
    """Accept the shared suite's staged selection only if it is exactly (part of) this release."""
    arches = {a["architecture"] for a in allowed}
    if (
        diff.get("suite") != SUITE
        or items(diff, "removed")
        or items(diff, "downgrades")
        or items(diff, "architectures_removed")
        or not set(items(diff, "architectures_added")) <= arches
    ):
        raise Fail("staged APT changes include removals, downgrades or unexpected architectures; refusing to publish")
    seen = set()
    for p in items(diff, "added"):
        key = (p.get("name"), p.get("architecture"))
        if key in seen or not any(matches(a, p) for a in allowed):
            raise Fail("staged APT changes include packages other than this release; refusing to publish")
        seen.add(key)
    upgraded = set()
    for u in items(diff, "upgrades"):
        key = (u.get("name"), u.get("architecture"))
        if key not in seen or key in upgraded or u.get("after") != allowed[0]["version"]:
            raise Fail("staged APT changes include an unrelated upgrade; refusing to publish")
        upgraded.add(key)
    size = sum(a["size"] for a in allowed if (a["name"], a["architecture"]) in seen)
    if diff.get("size_delta") != size:
        raise Fail("staged APT size does not match this release")
    token = diff.get("token")
    if not isinstance(token, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", token):
        raise Fail("invalid APT review token")
    return token, seen


def verify(debs=None):
    for a in debs or artifacts():
        p = published(public_index(a["architecture"]), a)
        if p is None:
            raise Fail(f"{a['file']} is not in the signed APT index")
        data = fetch(f"{ARCHIVE}/{pool_path(p.get('filename'))}", MAX_DEB, a["file"])
        if len(data) != a["size"] or sha256(data) != a["sha256"]:
            raise Fail(f"public download of {a['file']} differs from dist/")
        print(f"Verified APT: {a['file']} (signed metadata and exact package bytes)")


def publish():
    debs = artifacts()
    api = Api(*load_config())
    check_suite(api)
    missing = [a for a in debs if published(public_index(a["architecture"]), a) is None]
    if not missing:
        print("Already published; no repository changes.")
        return verify(debs)
    _, staged = review(api.call("/repository/diff"), missing)
    for a in missing:
        if (a["name"], a["architecture"]) in staged:
            print(f"{a['file']} already staged")
            continue
        print(f"Uploading {a['file']} to {SUITE}")
        upload = api.call("/uploads", a["bytes"], "application/vnd.debian.binary-package")
        if not matches(a, upload):
            raise Fail("upload metadata differs from the local package")
        if api.call(f"/uploads/{uuid(upload.get('id'))}/stage", b"{}").get("staged") is not True:
            raise Fail(f"{a['file']} was not staged")
    diff = api.call("/repository/diff")
    token, staged = review(diff, missing)
    if len(staged) != len(missing):
        raise Fail("staged selection does not include every package of this release")
    print(f"Reviewed {len(missing)} package addition(s); no removals or unrelated changes.")
    job = uuid(api.call("/repository/publish", json.dumps({"review_token": token}).encode()).get("job_id"))
    deadline = time.monotonic() + 300
    while True:
        state = api.call(f"/jobs/{job}")
        if state.get("id") != job:
            raise Fail("APT returned a different publication job")
        match state.get("state"):
            case "succeeded":
                break
            case "failed":
                raise Fail("publication job failed; inspect repository administration")
            case "running" if time.monotonic() < deadline:
                print("Publishing…")
                time.sleep(3)
            case _:
                raise Fail("publication still pending or unknown; inspect status before retrying")
    INDEX.clear()
    verify(debs)


def status():
    api = Api(*load_config())
    check_suite(api)
    d = api.call("/repository/diff")
    print(
        f"APT {SUITE} reachable; staged additions: {len(items(d, 'added'))}, removals: {len(items(d, 'removed'))}, "
        f"upgrades: {len(items(d, 'upgrades'))}, downgrades: {len(items(d, 'downgrades'))}"
    )


def main():
    commands = {"status": status, "publish": publish, "verify": verify}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        sys.exit(f"usage: {sys.argv[0]} {{{'|'.join(commands)}}}")
    try:
        commands[sys.argv[1]]()
    except (Fail, OSError) as e:
        sys.exit(f"apt-repo: {e}")


if __name__ == "__main__":
    main()
