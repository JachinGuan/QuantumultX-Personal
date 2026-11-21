"""Repository module policy and user-reported client state."""

import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
MODULE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


def load_modules(path):
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("模块登记表必须是 JSON 对象")
    for name, item in value.items():
        if (not MODULE_ID.fullmatch(name) or not isinstance(item, dict)
                or type(item.get("monitor_enabled")) is not bool or type(item.get("managed")) is not bool
                or "client_enabled" not in item
                or (item["client_enabled"] is not None and type(item["client_enabled"]) is not bool)
                or item.get("update_policy") not in ("review", "frozen")
                or item.get("risk_status") not in ("normal", "watch", "compatibility_concern")):
            raise ValueError("模块登记字段无效")
        if item["client_enabled"] is not None:
            report = item.get("client_report")
            if not isinstance(report, dict) or report.get("basis") != "user_report":
                raise ValueError("客户端开关记录须注明来自用户")
    return value


def select_sources(sources, modules):
    if not sources.keys() <= modules.keys() or any(
        item["monitor_enabled"] and name not in sources for name, item in modules.items()
    ):
        raise ValueError("监控来源与模块登记不一致")
    active = {name: source for name, source in sources.items() if modules[name]["monitor_enabled"]}
    return active, sorted(sources.keys() - active.keys())


def require_publication(module, registry):
    item = load_modules(registry).get(module)
    if item is None or not item["managed"]:
        raise ValueError("该模块未接管发布")
    if item["update_policy"] == "frozen":
        raise ValueError("该模块已冻结，禁止发布新版本")
