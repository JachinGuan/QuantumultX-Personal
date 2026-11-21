"""Collect bounded, redacted evidence from QX rules and JavaScript tokens."""

from dataclasses import dataclass
import re
from urllib.parse import urlsplit

EVIDENCE_LIMIT = 48
REFERENCE_LIMIT = 48
TOKEN = re.compile(
    r"//[^\n]*|/\*[\s\S]*?(?:\*/|\Z)|"
    r"""'(?:\\[\s\S]|[^'\\])*'|"(?:\\[\s\S]|[^"\\])*"|`(?:\\[\s\S]|[^`\\])*`|"""
    r"[A-Za-z_$][\w$]*|[^\s]"
)
QX_SCRIPT = re.compile(r"^\S+\s+url(?:-and-header)?\s+(script-[\w-]+)(?:\s+(.*))?$", re.I)
QX_RULE = re.compile(r"^\S+\s+url(?:-and-header)?\s+([\w-]+)(?:\s+(.*))?$", re.I)
MITM = re.compile(r"^hostname\s*=\s*(.+)$", re.I)
MITM_HOST = re.compile(r"(?:[-*?])?[a-z0-9.*?-]{1,85}", re.I)
SCRIPT_PATH = re.compile(r"""(?:^|[\s,])script-path\s*=\s*("[^"]*"|'[^']*'|[^\s,]+)""", re.I)
OPERAND = re.compile(r"""^(?:"([^"]*)"|'([^']*)'|([^\s,]+))""")
NETWORK_APIS = {"fetch", "Request", "WebSocket", "sendBeacon", "GM_xmlhttpRequest"}
LOADERS = {"require", "importScripts", "Worker", "SharedWorker", "getScript"}
SENSITIVE = {
    "cookie": "Cookie", "set-cookie": "Cookie", "authorization": "Authorization",
    "bearer": "Authorization", "token": "Token", "accesstoken": "Token", "refreshtoken": "Token",
    "apikey": "API key", "username": "账号", "password": "账号", "account": "账号",
}


@dataclass(frozen=True)
class Reference:
    target: str | None
    line: int
    mechanism: str


@dataclass(frozen=True)
class Finding:
    kind: str
    line: int
    evidence: str


@dataclass
class Scan:
    references: list
    findings: list
    limited: bool


def rewrite_scan(content):
    references = []
    findings = []
    for number, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//", "[")):
            continue
        action = QX_SCRIPT.match(line)
        paths = SCRIPT_PATH.findall(line)
        if rule := QX_RULE.match(line):
            findings.append(Finding("mutation", number, rule[1].lower()[:48]))
            operand = OPERAND.match(rule[2] or "")
            if not action and operand and rule[1] in ("301", "302", "307", "308"):
                target = next(value for value in operand.groups() if value is not None)
                findings.append(Finding("network", number, hostname(target) or "重写目标未知"))
        if match := MITM.match(line):
            values = re.split(r"\s+[#;]", match[1], maxsplit=1)[0]
            findings.extend(Finding("mitm", number, value.lower()) for value in re.split(r"[,\s]+", values)
                            if MITM_HOST.fullmatch(value))
        if paths:
            references.extend(Reference(path.strip("'\""), number, "script-path") for path in paths)
        elif action:
            match = OPERAND.match(action[2] or "")
            operand = next((value for value in match.groups() if value is not None), None) if match else None
            references.append(Reference(operand, number, "QX script action"))
    return bounded(references, findings)


def tokens(content):
    line, offset = 1, 0
    for match in TOKEN.finditer(content):
        line += content.count("\n", offset, match.start())
        value = match[0]
        if not value.startswith(("//", "/*")):
            yield value, line
        line += value.count("\n")
        offset = match.end()


def literal(token):
    if token and token[0] in ("'", '"', "`") and len(token) > 1:
        value = token[1:-1]
        if "\\" not in value and "${" not in value:
            return value
    return None


def hostname(value):
    if not value or not value.startswith(("https://", "http://")):
        return None
    try:
        host = urlsplit(value).hostname or ""
    except ValueError:
        return None
    return host if re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,84}", host) else None


def script_url(value):
    return value and re.search(r"\.(?:m?js|cjs)(?:[?#]|$)", value, re.I)


def arguments(items, start):
    """Return top-level argument tokens for a simple, bounded call expression."""
    depth = 0
    args = [[]]
    for token, _ in items[start:start + 80]:
        if token == ")" and depth == 0:
            return args
        if token == "," and depth == 0:
            args.append([])
            continue
        if token in ("(", "[", "{"):
            depth += 1
        elif token in (")", "]", "}"):
            depth -= 1
        args[-1].append(token)
    return []


def request_target(arg):
    if len(arg) == 1:
        return literal(arg[0])
    if arg and arg[0] == "{":
        for index in range(1, len(arg) - 2):
            if arg[index].strip("'\"") == "url" and arg[index + 1] == ":" and arg[index + 3:index + 4] in ([","], ["}"]):
                return literal(arg[index + 2])
    return None


def module_target(items, start):
    if start < len(items) and literal(items[start][0]) is not None:
        return literal(items[start][0])
    for index in range(start, min(len(items) - 1, start + 64)):
        token = items[index][0]
        if token == "from":
            return literal(items[index + 1][0])
        if token in (";", "import", "export", "="):
            break
    return None


def javascript_scan(content):
    items = list(tokens(content))
    references, findings = [], []
    for index, (token, line) in enumerate(items):
        following = [value for value, _ in items[index + 1:index + 4]]
        previous = [value for value, _ in items[max(0, index - 3):index]]
        call = following[:1] == ["("]
        if (token in LOADERS or token == "import") and call:
            args = arguments(items, index + 2)
            targets = args if token == "importScripts" else args[:1]
            references.extend(Reference(literal(arg[0]) if len(arg) == 1 else None, line, token)
                              for arg in targets or [[]])
        elif token == "import" and following[:1] != ["."] and previous[-1:] != ["."]:
            references.append(Reference(module_target(items, index + 1), line, "import"))
        elif token == "export" and following[:1] in (["*"], ["{"]):
            target = module_target(items, index + 1)
            if target is not None or following[:1] == ["*"]:
                references.append(Reference(target, line, "export from"))
        if token == "src" and previous[-1:] == ["."] and following[:1] == ["="]:
            value = literal(following[1]) if len(following) > 1 and following[2:] in ([";"], []) else None
            if script_url(value) or any(value == "createElement" for value, _ in items[max(0, index - 40):index]):
                references.append(Reference(value, line, "script.src"))
        xhr_open = token == "open" and previous[-1:] == ["."] and any(
            value == "XMLHttpRequest" for value, _ in items[max(0, index - 80):index]
        )
        if call and (token in NETWORK_APIS or previous[-2:] in (["$httpClient", "."], ["axios", "."])
                     or token == "axios" or xhr_open):
            args = arguments(items, index + 2)
            offset = 1 if xhr_open else 0
            target = request_target(args[offset]) if len(args) > offset else None
            host = hostname(target)
            findings.append(Finding("network", line, host or "网络目的地未知"))
            if script_url(target):
                references.append(Reference(target, line, "network script URL"))
        name = (literal(token) or token).lower().replace("_", "").replace("-", "")
        sensitive = SENSITIVE.get(name) or (SENSITIVE.get("token") if name.endswith("token") and len(name) < 32 else None)
        if sensitive:
            context = [value for value, _ in items[max(0, index - 5):index + 6]]
            if "headers" in context:
                sensitive += "（请求头上下文）"
            findings.append(Finding("sensitive", line, sensitive))
        if token in ("$prefs", "$persistentStore", "localStorage", "sessionStorage"):
            operation = following[1] if len(following) >= 2 and following[0] == "." else ""
            evidence = "存储写入或删除" if operation in ("write", "setValueForKey", "setItem", "removeItem", "clear", "removeValueForKey") else "访问持久化存储"
            findings.append(Finding("storage", line, evidence))
        if token in ("eval", "Function", "atob", "fromCharCode", "unescape") and call:
            findings.append(Finding("execution", line, token))
            if token in ("eval", "Function"):
                references.append(Reference(None, line, "dynamic execution"))
        if token in ("setTimeout", "setInterval") and call and len(following) > 1 and literal(following[1]) is not None:
            findings.append(Finding("execution", line, "字符串定时器"))
            references.append(Reference(None, line, "string timer"))
        if re.fullmatch(r"_0x[0-9a-f]{4,}", token, re.I):
            findings.append(Finding("execution", line, "疑似混淆标识符"))
        if token in ("headers", "body") and (previous[-2:] in (["$request", "."], ["$response", "."])
                                             or following[:1] == [":"]):
            following_tokens = [value for value, _ in items[index + 1:index + 6]]
            mutable = (following[:1] in (["="], [":"]) or "=" in following_tokens
                       or "delete" in [value for value, _ in items[max(0, index - 5):index]])
            findings.append(Finding("mutation", line, token + (" 可能写入或转发" if mutable else " 访问")))
    return bounded(references, findings)


def bounded(references, findings):
    references = list(dict.fromkeys(references))
    findings = list(dict.fromkeys(findings))
    return Scan(references[:REFERENCE_LIMIT], findings[:EVIDENCE_LIMIT],
                len(references) > REFERENCE_LIMIT or len(findings) > EVIDENCE_LIMIT)
