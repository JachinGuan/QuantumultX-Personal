"""Validate external QX resources as text and record findings in GitHub Issue #1."""

import argparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 2 * 1024 * 1024
FEATURE_LIMIT = 12
BEGIN = "<!-- QX_STATE_BEGIN -->"
END = "<!-- QX_STATE_END -->"
ISSUE_TITLE = "[QX Monitor] Upstream change log"
SHA256 = re.compile(r"[0-9a-f]{64}")
HOST = re.compile(r"[a-z0-9][a-z0-9.-]{0,84}", re.I)
MITM = re.compile(r"(?:[-*?])?[a-z0-9.*?-]{1,85}", re.I)
URL = re.compile(r"""https?://[^\s"'<>()[\]{},`\\]+""", re.I)
IMPORT_URL = re.compile(
    r"""\b(?:import|require|importScripts|from)\b[ \t]*(?:\([ \t]*)?['"](https?://[^\s'"]+)""",
    re.I,
)
GROUPS = ("mitm", "dependencies", "destinations", "operations", "sensitive", "execution")
HOSTNAME = re.compile(r"^hostname\s*=\s*(.+)$", re.I)
RULE = re.compile(
    r"^\S+\s+(?:url(?:-and-header)?)\s+(\d{3}|reject[\w-]*|"
    r"script-[\w-]+|(?:request|response)-[\w-]+|header(?:-replace)?|"
    r"echo-response|redirect|allow)(?=\s|$)", re.I
)
JS = re.compile(
    r"\b(?:const|let|var)\s+[$\w]+\s*=|\bfunction\s*[$\w]*\s*\(|=>|"
    r"\$(?:done|task\.fetch|httpClient\.\w+)\s*\(|"
    r"\b(?:import|export)\s+|\b(?:eval|fetch|require|alert)\s*\("
)
CHALLENGE = re.compile(
    r"/cdn-cgi/challenge-platform|cf-browser-verification|cf-chl-|"
    r"enable javascript and cookies to continue|verify (?:that )?you are (?:a )?human|"
    r"g-recaptcha|h-captcha|attention required!\s*\|\s*cloudflare", re.I
)
HTML = re.compile(
    r"^\s*(?:<!doctype\s+html|<!--|<\?xml|<(?:html|head|body|title|script|meta|div|h1|form)\b)",
    re.I
)
FEATURES = {
    "sensitive": {
        "Cookie": r"\b(?:set[-_]?)?cookie(?:s|Store)?\b",
        "Authorization": r"\bauthorization\b",
        "Token/API key": r"\b(?:[a-z]+[-_])?(?:token|api[-_]?key|bearer)\b|\b(?:access|refresh|auth)Token\b",
        "Persistent storage": r"\$(?:prefs\.valueForKey|persistentStore\.read|keychain)\b",
    },
    "execution": {
        "eval": r"\beval\s*(?:\?\.)?\s*\(",
        "Function constructor": r"\bFunction\s*\(",
        "Dynamic loading": r"\b(?:import|require|importScripts)\s*\(|\bcreateElement\s*\(\s*['\"]script",
        "Obfuscation indicators": r"\b(?:atob|unescape|fromCharCode)\s*\(|(?:\\(?:x[0-9a-f]{2}|u[0-9a-f]{4})){6,}|\b_0x[0-9a-f]{4,}\b",
        "String timer": r"""\bset(?:Timeout|Interval)\s*\(\s*["']""",
    },
}
NETWORK = re.compile(
    r"\$(?:task\.fetch|httpClient\.\w+)\s*\(|\b(?:fetch|axios(?:\.\w+)?|"
    r"XMLHttpRequest|WebSocket|sendBeacon|GM_xmlhttpRequest)\s*\(", re.I
)
JS_MUTATIONS = {
    "Body": r"\$(?:request|response)\s*\.\s*body\b|\bbody\s*:",
    "Headers": r"\$(?:request|response)\s*\.\s*headers\b|\bheaders\s*:",
}


class InvalidContent(ValueError):
    """A response failed a documented validation check."""


@dataclass
class Observation:
    sha256: str = ""
    profile: dict | None = None
    error: str = ""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def https_parts(url):
    try:
        parts = urlsplit(url)
        if (parts.scheme == "https" and parts.hostname and parts.port in (None, 443)
                and parts.username is None and parts.password is None and not parts.fragment):
            return parts
    except ValueError:
        pass
    raise InvalidContent("URL is not an allowed HTTPS endpoint")


def check_target(source, url):
    original = https_parts(source["url"])
    target = https_parts(url)
    if target.hostname == original.hostname and target.path == original.path and target.query == original.query:
        return
    if original.hostname == target.hostname == "github.com" and "redirect_hosts" in source:
        release_prefix = original.path.split("/latest/download/", 1)[0] + "/download/"
        if target.path.startswith(release_prefix) and target.path.endswith("/" + original.path.split("/")[-1]):
            return
    if target.hostname == original.hostname and target.path in ("", "/"):
        raise InvalidContent("source redirected to the site homepage")
    if target.hostname in source.get("redirect_hosts", ()):
        return
    raise InvalidContent("redirect or final URL outside the source's allowed endpoints")


class CheckedRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 4

    def __init__(self, check):
        self.check = check

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.check(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def rewrite_parts(content):
    rules = []
    mitm = set()
    for line in map(str.strip, content.splitlines()):
        if not line or line.startswith(("#", ";", "//")):
            continue
        if match := HOSTNAME.match(line):
            value_list = re.split(r"\s+[#;]", match[1], maxsplit=1)[0]
            mitm.update(value.lower() for value in re.split(r"[,\s]+", value_list)
                        if MITM.fullmatch(value) and value not in ("-", "*-"))
        if match := RULE.match(line):
            rules.append((match[1].lower(), line))
    return rules, mitm


def validate(data, media_type, kind):
    if not 0 < len(data) <= LIMIT:
        raise InvalidContent("empty response or file exceeds 2 MiB")
    try:
        body = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InvalidContent("response is not UTF-8 text") from exc
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", body):
        raise InvalidContent("response contains binary control characters")
    if HTML.match(body) or media_type in ("text/html", "application/xhtml+xml"):
        if CHALLENGE.search(body):
            raise InvalidContent("HTML access challenge (Cloudflare or CAPTCHA indicators)")
        raise InvalidContent("HTML or XML page instead of the expected resource")
    common = {"text/plain", "application/octet-stream", "binary/octet-stream"}
    script_types = {"text/javascript", "application/javascript", "application/x-javascript",
                    "text/ecmascript", "application/ecmascript"}
    allowed = common | (script_types if kind == "javascript" else {"text/x-conf"})
    if media_type not in allowed:
        raise InvalidContent("missing or unexpected Content-Type")
    if kind == "rewrite":
        if not rewrite_parts(body)[0]:
            raise InvalidContent("no recognized Quantumult X URL rewrite rules")
    else:
        code = re.sub(r"^\s*//[^\n]*|^\s*/\*[\s\S]*?\*/", "", body, flags=re.M)
        if not JS.search(code):
            raise InvalidContent("no recognizable JavaScript code")
    return body


def url_features(content):
    for url in URL.findall(content):
        try:
            parts = urlsplit(url)
            if parts.hostname and HOST.fullmatch(parts.hostname):
                yield url, parts
        except ValueError:
            continue


def profile(content, kind):
    rules, mitm = rewrite_parts(content) if kind == "rewrite" else ([], set())
    dependencies = set()
    destinations = set()
    operations = set()
    code = content
    if kind == "rewrite":
        code = "\n".join(line for _, line in rules)
        for action, line in rules:
            operations.add(action[:50])
            operands = line.split()[3:]
            for operand in operands:
                for url, parts in url_features(operand):
                    if action.startswith("script-") or parts.path.lower().endswith((".js", ".mjs")):
                        dependencies.add(parts.hostname + "/" + digest(url.encode())[:16])
                    else:
                        destinations.add(parts.hostname)
    else:
        imports = set(IMPORT_URL.findall(code))
        # Include literal URL candidates, since static text cannot establish data flow.
        for url, parts in url_features(code):
            destinations.add(parts.hostname)
            if parts.path.lower().endswith((".js", ".mjs")) or url in imports:
                dependencies.add(parts.hostname + "/" + digest(url.encode())[:16])
        if NETWORK.search(code):
            operations.add("Network API usage")
        if re.search(r"\$done\s*\(", code):
            operations.update(label for label, pattern in JS_MUTATIONS.items() if re.search(pattern, code))
    groups = {
        "mitm": mitm, "dependencies": dependencies, "destinations": destinations,
        "operations": operations,
        **{group: {label for label, pattern in patterns.items() if re.search(pattern, code, re.I)}
           for group, patterns in FEATURES.items()},
    }
    return {
        **{key: sorted(values)[:FEATURE_LIMIT] for key, values in groups.items()},
        "truncated": sorted(key for key, values in groups.items() if len(values) > FEATURE_LIMIT),
        "rule_count": len(rules),
        "rules_sha256": digest("\n".join(line for _, line in rules).encode()) if rules else "",
    }


def observe(source):
    result = Observation()
    opener = urllib.request.build_opener(CheckedRedirect(lambda url: check_target(source, url)))
    try:
        check_target(source, source["url"])
        req = urllib.request.Request(source["url"], headers={"User-Agent": "QX-upstream-monitor/2.0"})
        with opener.open(req, timeout=15) as response:
            check_target(source, response.geturl())
            if response.status != 200:
                raise InvalidContent(f"unexpected HTTP status {response.status}")
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise InvalidContent("unsupported response encoding")
            declared = response.headers.get("Content-Length")
            if declared is not None and (not re.fullmatch(r"[0-9]{1,10}", declared) or int(declared) > LIMIT):
                raise InvalidContent("invalid Content-Length or file exceeds 2 MiB")
            data = response.read(LIMIT + 1)
            if len(data) <= LIMIT:
                result.sha256 = digest(data)
            if declared is not None and len(data) != int(declared):
                raise InvalidContent("response size does not match Content-Length")
            media_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        result.profile = profile(validate(data, media_type, source["kind"]), source["kind"])
    except urllib.error.HTTPError as exc:
        result.error = f"HTTP {exc.code}"
        exc.close()
    except InvalidContent as exc:
        result.error = str(exc)
    except (OSError, HTTPException) as exc:
        result.error = f"download failed ({type(exc).__name__})"
    return result


def read_state(body):
    if not isinstance(body, str) or body.count(BEGIN) != 1 or body.count(END) != 1:
        raise ValueError("Issue #1 is missing a unique baseline block")
    _, _, tail = body.partition(BEGIN)
    raw, end, _ = tail.partition(END)
    state = json.loads(raw)
    if not end or not isinstance(state, dict) or not state:
        raise ValueError("Issue #1 baseline is empty or malformed")
    for name, entry in state.items():
        if (not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) or not isinstance(entry, dict)
                or not isinstance(entry.get("url"), str)
                or not SHA256.fullmatch(str(entry.get("sha256", "")))):
            raise ValueError("Issue #1 baseline contains an invalid source record")
        if "legacy_sha256" in entry and not SHA256.fullmatch(str(entry["legacy_sha256"])):
            raise ValueError("Issue #1 baseline contains an invalid legacy hash")
        if "profile" in entry:
            validate_profile(entry["profile"])
    return state


def validate_profile(saved):
    if not isinstance(saved, dict):
        raise ValueError("Issue #1 baseline contains an invalid static profile")
    for key in (*GROUPS, "truncated"):
        values = saved.get(key)
        if (not isinstance(values, list) or len(values) > FEATURE_LIMIT
                or any(not isinstance(value, str) or len(value) > 105 for value in values)):
            raise ValueError("Issue #1 baseline contains an invalid static feature list")
    count = saved.get("rule_count")
    rules_hash = saved.get("rules_sha256")
    if (type(count) is not int or not 0 <= count <= LIMIT or not isinstance(rules_hash, str)
            or (rules_hash != "" and not SHA256.fullmatch(rules_hash))):
        raise ValueError("Issue #1 baseline contains invalid rewrite rule metadata")


def displayed(values):
    # Treat even values retrieved from the editable issue state as untrusted.
    values = sorted(values)
    safe = [re.sub(r"[^A-Za-z0-9 ./*?_-]", "?", value[:105]) for value in values[:4]]
    return ", ".join(f"`{value}`" for value in safe) + (f" (+{len(values) - 4} more)" if len(values) > 4 else "")


def compare(old, new):
    changes = []
    reasons = []
    high = False
    comparable = old is not None
    if not comparable:
        changes.append("Previous static profile unavailable. Listed features are current observations.")
        old = {}
    for key, label in (
        ("mitm", "MITM hostname patterns"), ("dependencies", "remote JavaScript dependencies"),
        ("destinations", "possible network destination domains"), ("operations", "rewrite or script behaviors"),
        ("sensitive", "sensitive-data indicators"), ("execution", "execution or obfuscation indicators"),
    ):
        added = set(new[key]) - set(old.get(key, []))
        removed = set(old.get(key, [])) - set(new[key])
        if added:
            changes.append(f"{label}{' (+)' if comparable else ''}: {displayed(added)}")
            reasons.append(label)
            if key == "mitm" and comparable and any(not host.startswith("-") for host in added):
                reasons.append("potential MITM scope expansion")
            if key in ("execution", "sensitive") or key == "mitm" and any(
                    ("*" in host or "?" in host) and not host.startswith("-") for host in added):
                high = True
        if removed:
            changes.append(f"{label} (−) {displayed(removed)}")
            if key == "mitm":
                reasons.append("MITM scope changed (including exclusion patterns)")
                if any(host.startswith("-") for host in removed):
                    reasons.append("potential MITM scope expansion (removed exclusion)")
                    high = True
    if new["rules_sha256"] != old.get("rules_sha256", ""):
        changes.append(f"Rewrite rules changed ({old.get('rule_count', 0)} → {new['rule_count']} captured)."
                       if "rule_count" in old else f"Captured rewrite rules: {new['rule_count']}.")
    if new["truncated"] or old.get("truncated"):
        changes.append("Feature lists reached the storage limit. An indicated removal or addition may reflect truncation.")
        reasons.append("partial feature comparison")
    risk = "High" if high else "Medium" if reasons else "Low (limited static evidence)"
    return changes, risk, reasons


def duplicates(observations):
    by_hash = defaultdict(set)
    for name, url, sha in observations:
        if sha:
            by_hash[sha].add((name, url))
    return [
        f"- `{sha}` shared by {displayed({name for name, _ in pairs})}"
        for sha, pairs in sorted(by_hash.items())
        if len({url for _, url in pairs}) > 1
    ]


def summarize(sources, previous, observations):
    current = previous.copy()
    changes, failures = [], []
    for name, source in sources.items():
        old = previous.get(name, {})
        result = observations[name]
        old_sha = old.get("sha256", "")
        if result.error:
            failures.append(f"- **{name}** — {result.error}; observed hash: "
                            f"{result.sha256 or 'unavailable'}; baseline retained: {old_sha or 'none'}.")
            continue
        old_profile = old.get("profile") if old.get("url") == source["url"] else None
        current[name] = {
            "url": source["url"], "sha256": result.sha256, "profile": result.profile,
            **({"legacy_sha256": old["legacy_sha256"]} if "legacy_sha256" in old else
               {"legacy_sha256": old_sha} if old_sha and "profile" not in old else {}),
        }
        if old_sha == result.sha256 and old_profile == result.profile:
            continue
        details, risk, reasons = compare(old_profile, result.profile)
        if old.get("url") and old["url"] != source["url"]:
            details.insert(0, "Configured source URL changed.")
        if not old_profile and not reasons:
            risk = "Uncertain (no comparable static profile)"
        changes += [
            f"#### {name}",
            f"- SHA-256: `{old_sha or 'none'}` → `{result.sha256}`",
            "- Content passed HTTP and basic structure checks.",
            f"- Risk: **{risk}**. Basis: {', '.join(reasons) or 'no new monitored risk indicators identified'}.",
            "- Manual review: recommended.",
            *(f"- {detail}" for detail in details or ["Bytes changed; tracked static features stayed the same."]),
            "",
        ]
    repeated = duplicates((name, source["url"], observations[name].sha256) for name, source in sources.items())
    historical = duplicates(
        (name, entry["url"], entry.get("legacy_sha256", entry["sha256"] if "profile" not in entry else ""))
        for name, entry in current.items()
    )
    return current, changes, failures, repeated, historical


def render(sources, previous, observations):
    current, changes, failures, repeated, historical = summarize(sources, previous, observations)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    report = "\n".join([
        f"## Last check: {now}", "", "### Changes and baseline validation",
        *(changes or ["- No validated changes."]), "", "### Download and validation failures",
        *(failures or ["- None."]), "", "### Identical hashes in this run",
        *(repeated or ["- None observed."]), "", "### Identical hashes in legacy baselines",
        *(historical or ["- None recorded."]), "",
        "Identical hashes across URLs indicate identical response bytes. Review delivery errors or shared content.",
        "Static findings are heuristic. They cannot establish safety. No third-party code was executed or published.",
    ])
    state = json.dumps(current, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c")
    body = f"{report}\n\n{BEGIN}\n{state}\n{END}"
    if len(body) > 65536:
        raise ValueError("report and baseline exceed the GitHub Issue body limit")
    return report, body, bool(changes)


def github_request(repo, token, suffix="", payload=None, method="GET"):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("Invalid GH_REPO")
    url = f"https://api.github.com/repos/{repo}/issues/1{suffix}"

    def no_redirect(_):
        raise InvalidContent("unexpected GitHub API redirect")

    req = urllib.request.Request(url, method=method, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "User-Agent": "qx-upstream-monitor", "Content-Type": "application/json",
    }, data=json.dumps(payload).encode() if payload is not None else None)
    with urllib.request.build_opener(CheckedRedirect(no_redirect)).open(req, timeout=20) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="print findings and skip all GitHub issue requests")
    parser.add_argument("--baseline", type=Path, help="saved issue body to use with --dry-run")
    args = parser.parse_args()
    if args.baseline and not args.dry_run:
        parser.error("--baseline requires --dry-run")
    sources = json.loads((ROOT / "upstream/sources.json").read_text())
    for name, source in sources.items():
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) or source["kind"] not in ("rewrite", "javascript"):
            raise ValueError("Invalid source manifest")
    if args.dry_run:
        previous = read_state(args.baseline.read_text()) if args.baseline else {}
    else:
        repo, token = os.environ["GH_REPO"], os.environ["GH_TOKEN"]
        issue = github_request(repo, token)
        if issue.get("title") != ISSUE_TITLE or "pull_request" in issue:
            raise ValueError("Issue #1 does not match the monitor issue")
        previous = read_state(issue["body"])
    with ThreadPoolExecutor(max_workers=5) as pool:
        observations = dict(zip(sources, pool.map(observe, sources.values())))
    report, body, changed = render(sources, previous, observations)
    # A single API update commits the observation and baseline together. The
    # separate comment preserves substantive checks in the issue timeline.
    if not args.dry_run:
        if changed:
            github_request(repo, token, "/comments", {"body": report}, "POST")
        github_request(repo, token, payload={"body": body}, method="PATCH")
        print(f"Checked {len(sources)} sources; details recorded in Issue #1.")
    else:
        print(report)


if __name__ == "__main__":
    main()
