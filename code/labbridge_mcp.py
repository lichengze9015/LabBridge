#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LabBridge MCP Server —— 零第三方依赖实现（仅 Python 标准库）

反溯说明 / Provenance
---------------------
本文件依据 MCP 协议的**公开行为规范**（initialize / tools/list / tools/call 三种
JSON-RPC 2.0 方法、stdio 传输、能力协商）独立编写，**未参考、未复制
modelcontextprotocol/servers 仓库的任何源码**。

这样做的理由：modelcontextprotocol/servers 正处于 MIT → Apache-2.0 许可过渡期，
新旧贡献的许可头并存，二次分发需逐文件核对。而从协议行为层面重写，产出的是
自己的表达，许可状态单一可控（本项目沿用 Apache-2.0）。

用法:
    python labbridge_mcp.py                 # stdio 模式（供 MCP 客户端连接）
    python labbridge_mcp.py --selftest      # 内置自检，不依赖任何客户端

设计约束（来自文档集 04 / 05 / 07）：
    1. 只读旁路：不提供任何向仪器下发指令的工具。
    2. 脱敏默认开启：敏感字段默认掩码，原文需显式申请并记例外。
    3. 全程留痕：每次工具调用落审计日志（时间戳 + SHA-256 + actor）。
    4. 不下临床结论：审核输出只出「待关注列表」，措辞禁止「已审核/已签发/结论为」。
"""

import sys
import json
import time
import uuid
import hashlib
import datetime
import os
import re
from typing import Any, Dict, List, Optional

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "labbridge", "version": "1.0.0"}

# ---------------------------------------------------------------------------
# 数据分级规则（文档 02 / 05）—— 人定规则，机器执行，人审例外
# ---------------------------------------------------------------------------

# 字段 -> 敏感等级。这是「规则层」的机器可读形态，人签署后生效。
FIELD_CLASS: Dict[str, str] = {
    "patient_name": "sensitive",
    "dob": "sensitive",
    "address": "sensitive",
    "phone": "sensitive",
    "id_card": "sensitive",
    "patient_id": "internal",
    "sex": "internal",
    "test_item": "internal",
    "result_value": "internal",
    "unit": "internal",
    "ref_range": "internal",
    "abnormal_flag": "internal",
    "instrument_note": "internal",
}

# 用户等级 -> 各等级字段可见形态（文档 05 权限矩阵）
FORM_MATRIX: Dict[str, Dict[str, str]] = {
    "engineer":  {"public": "raw",    "internal": "raw",   "sensitive": "mask"},
    "director":  {"public": "raw",    "internal": "raw",   "sensitive": "mask"},
    "lead":      {"public": "raw",    "internal": "raw",   "sensitive": "hidden"},
    "technician": {"public": "raw",   "internal": "raw",   "sensitive": "hidden"},
    "auditor":   {"public": "raw",    "internal": "raw",   "sensitive": "mask"},
}

# 脱敏后回扫正则（文档 02：脱敏正确率 100%）
LEAK_PATTERNS = [
    (r"\d{17}[\dXx]", "id_card"),
    (r"1[3-9]\d{9}", "phone"),
]

# 审核规则（文档 04：三条最小规则）
# V2.5：阈值以受控文件 config/critical_values.yaml 为唯一来源。
# 旧实现在这里硬编码 4 项（K/GLU/HGB/PLT），而受控表有 8 项（另有 WBC/RBC/CREA/ALT），
# 结果 WBC 35.0 这类明确超阈值的值在这条链路上不判危急 —— 两份阈值各说各话。
# 保留下表仅作配置缺失时的兜底，正常路径应读到 yaml。
_FALLBACK_CRITICAL: Dict[str, Dict[str, float]] = {
    "K":    {"low": 2.5, "high": 6.5},
    "GLU":  {"low": 2.2, "high": 27.8},
    "HGB":  {"low": 50.0, "high": 200.0},
    "PLT":  {"low": 20.0, "high": 1000.0},
    "WBC":  {"low": 1.0, "high": 30.0},
    "RBC":  {"low": 1.5, "high": 8.0},
    "CREA": {"low": 20.0, "high": 700.0},
    "ALT":  {"low": 1.0, "high": 1000.0},
}

_CRIT_CACHE: Optional[Dict[str, Dict[str, float]]] = None


def critical_values() -> Dict[str, Dict[str, float]]:
    """读受控阈值；读不到才退回内置兜底。结果缓存，避免每次调用都解析 YAML。"""
    global _CRIT_CACHE
    if _CRIT_CACHE is not None:
        return _CRIT_CACHE
    table: Dict[str, Dict[str, float]] = {}
    try:
        from labbridge_config import Config
        raw = ((Config().critical or {}).get("values") or {})
        for k, v in raw.items():
            if isinstance(v, dict) and v.get("low") is not None and v.get("high") is not None:
                table[str(k).upper()] = {"low": float(v["low"]), "high": float(v["high"])}
    except Exception:
        table = {}
    _CRIT_CACHE = table or dict(_FALLBACK_CRITICAL)
    return _CRIT_CACHE

FORBIDDEN_WORDING = ["已审核", "已签发", "结论为", "诊断"]


# ---------------------------------------------------------------------------
# 审计日志（文档 05 第六章 / 第七章）
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _sha256(obj: Any) -> str:
    payload = json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


AUDIT_LOG: List[Dict[str, Any]] = []
AUDIT_LOG_PATH = os.environ.get("LABBRIDGE_AUDIT_LOG", "audit_log.jsonl")


def audit_log(**kw: Any) -> Dict[str, Any]:
    """统一日志中间件。所有工具调用必须经过它。"""
    rec = {
        "event_id": str(uuid.uuid4()),
        "timestamp": _now_iso(),
        "actor_id": kw.get("actor_id", "unknown"),
        "actor_role": kw.get("actor_role", "technician"),
        "action": kw.get("action", ""),
        "object": kw.get("object", ""),
        "data_class": kw.get("data_class", "internal"),
        "field_form": kw.get("field_form", "raw"),
        "policy_hit": kw.get("policy_hit", ""),
        "agent_version": SERVER_INFO["version"],
        "data_source": kw.get("data_source", ""),
        "human_involved": kw.get("human_involved", False),
        "result": kw.get("result", "ok"),
    }
    rec["hash"] = _sha256({k: v for k, v in rec.items() if k != "hash"})
    AUDIT_LOG.append(rec)
    try:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass  # 日志落盘失败不阻断主流程，但内存副本仍在
    return rec


# ---------------------------------------------------------------------------
# 工具实现
# ---------------------------------------------------------------------------

def _mask(value: Any) -> Any:
    s = str(value)
    if len(s) <= 2:
        return "*" * len(s)
    return s[0] + "*" * (len(s) - 2) + s[-1]


def _form_for(role: str, level: str) -> str:
    return FORM_MATRIX.get(role, FORM_MATRIX["technician"]).get(level, "hidden")


def tool_deidentify(args: Dict[str, Any]) -> Dict[str, Any]:
    """按字段分级脱敏。默认掩码；原文需显式 request_raw=True 并记例外。"""
    records = args.get("records") or []
    role = args.get("actor_role", "technician")
    request_raw = bool(args.get("request_raw", False))

    out, exceptions, leaks = [], [], []
    for rec in records:
        new = {}
        for k, v in rec.items():
            level = FIELD_CLASS.get(k, "internal")
            form = _form_for(role, level)
            if form == "hidden":
                continue
            if level == "sensitive" and form == "mask" and not request_raw:
                new[k] = _mask(v)
            else:
                new[k] = v
                if level == "sensitive":
                    exceptions.append({"field": k, "reason": "request_raw"})
        out.append(new)

    # 脱敏后回扫（文档 02：脱敏正确率 100%）
    for rec in out:
        for k, v in rec.items():
            for pat, tag in LEAK_PATTERNS:
                if re.search(pat, str(v)):
                    leaks.append({"field": k, "pattern": tag})
                    rec[k] = "[REDACTED]"

    audit_log(actor_id=args.get("actor_id", "unknown"), actor_role=role,
              action="deidentify", object=f"{len(records)} records",
              data_class="sensitive", field_form="mask",
              policy_hit="field-class-default", data_source=args.get("data_source", ""),
              human_involved=request_raw,
              result="leak_blocked" if leaks else "ok")

    return {
        "records": out,
        "exceptions": exceptions,
        "leak_hits": leaks,
        "deidentify_ok": not leaks,
    }


def tool_normalize(args: Dict[str, Any]) -> Dict[str, Any]:
    """ASTM 记录 / OCR 结构 -> 统一结果模型。"""
    raw = args.get("raw_records") or []
    unified = []
    for r in raw:
        unified.append({
            "patient_pseudo_id": r.get("patient_id") or r.get("pid") or "",
            "sex": r.get("sex", ""),
            "test_item": r.get("test_item") or r.get("item") or "",
            "result_value": _to_float(r.get("result_value") or r.get("value")),
            "unit": r.get("unit", ""),
            "ref_range": r.get("ref_range", ""),
            "abnormal_flag": r.get("abnormal_flag", ""),
            "instrument_note": r.get("instrument_note", ""),
        })
    audit_log(actor_id=args.get("actor_id", "unknown"), action="normalize",
              object=f"{len(raw)} raw records", data_class="internal",
              field_form="raw", policy_hit="unified-model-v1",
              data_source=args.get("data_source", ""))
    return {"unified": unified, "count": len(unified)}


def _to_float(v: Any) -> Optional[float]:
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None


def tool_screen(args: Dict[str, Any]) -> Dict[str, Any]:
    """最小审核规则引擎：异常标志聚合 / 危急值预筛 / 趋势漂移。
    只输出「待关注列表」，不下临床结论。"""
    results = args.get("results") or []
    flags: List[Dict[str, Any]] = []

    def add(rule, item, reason, extra=None):
        flags.append({"rule": rule, "test_item": item,
                      "reason": reason, **(extra or {})})

    # R1 异常标志聚合
    for r in results:
        if str(r.get("abnormal_flag", "")).upper() in ("H", "L", "HH", "LL"):
            add("R1", r.get("test_item"), f"仪器异常标志 {r.get('abnormal_flag')}")

    # R2 危急值预筛（V2.5：阈值来自受控 config，含 WBC/RBC/CREA/ALT）
    _th_table = critical_values()
    for r in results:
        th = _th_table.get(str(r.get("test_item", "")).upper())
        val = r.get("result_value")
        if th and isinstance(val, (int, float)):
            if val <= th["low"] or val >= th["high"]:
                add("R2", r.get("test_item"), f"超出危急值阈值 {val}",
                    {"urgent": True})

    # R3 趋势漂移（同一患者短期内同项目显著漂移）
    window = int(args.get("window_days", 7))
    drift_pct = float(args.get("drift_pct", 30))
    by_patient: Dict[str, Dict[str, List[float]]] = {}
    for r in results:
        pid = r.get("patient_pseudo_id", "")
        item = r.get("test_item", "")
        val = r.get("result_value")
        if isinstance(val, (int, float)):
            by_patient.setdefault(pid, {}).setdefault(item, []).append(val)
    for pid, items in by_patient.items():
        for item, vals in items.items():
            if len(vals) >= 2:
                base = vals[0]
                if base:
                    delta = abs(vals[-1] - base) / abs(base) * 100
                    if delta >= drift_pct:
                        add("R3", item, f"{window} 天内漂移 {delta:.1f}%",
                            {"patient_pseudo_id": pid})

    audit_log(actor_id=args.get("actor_id", "unknown"), action="screen",
              object=f"{len(results)} results", data_class="internal",
              field_form="raw", policy_hit="R1;R2;R3",
              human_involved=True,
              result="flagged" if flags else "clean")

    return {
        "watchlist": flags,
        "count": len(flags),
        "urgent_count": sum(1 for f in flags if f.get("urgent")),
        "notice": "本列表为待人工关注项，不构成审核结论，不替代签字。",
    }


def tool_check_wording(args: Dict[str, Any]) -> Dict[str, Any]:
    """输出措辞合规检查（文档 03/04：禁止「AI 替代签字」的表述）。"""
    text = args.get("text", "")
    hits = [w for w in FORBIDDEN_WORDING if w in text]
    audit_log(actor_id=args.get("actor_id", "unknown"), action="check_wording",
              object=f"{len(text)} chars", data_class="internal",
              result="blocked" if hits else "ok")
    return {"forbidden_hits": hits, "compliant": not hits}


def tool_evidence_pack(args: Dict[str, Any]) -> Dict[str, Any]:
    """生成证据包目录骨架 + manifest（文档 08 4.2）。"""
    root = args.get("output_dir", "evidence_pack")
    stage = args.get("stage", "demo")
    tree = [
        "00_方针与范围", "01_风险与评估", "02_规则与权限", "03_运行日志",
        "04_变更与版本", "05_CAPA", "06_监视测量", "07_不适用声明", "08_资产包",
    ]
    created = []
    for d in tree:
        p = os.path.join(root, d)
        try:
            os.makedirs(p, exist_ok=True)
            created.append(p)
        except OSError as e:
            return {"error": f"mkdir failed: {e}"}

    manifest = {
        "stage": stage,
        "generated_at": _now_iso(),
        "agent_version": SERVER_INFO["version"],
        "directories": tree,
        "audit_events_in_session": len(AUDIT_LOG),
        "audit_log_sha256": _sha256([r["hash"] for r in AUDIT_LOG]),
    }
    manifest["manifest_sha256"] = _sha256(
        {k: v for k, v in manifest.items() if k != "manifest_sha256"})
    try:
        with open(os.path.join(root, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
    except OSError as e:
        return {"error": f"write manifest failed: {e}"}

    audit_log(actor_id=args.get("actor_id", "unknown"), action="build_evidence_pack",
              object=root, data_class="internal", human_involved=True,
              result="ok")
    return {"root": root, "created": created, "manifest": manifest}


TOOLS: Dict[str, Any] = {
    "lb_deidentify": {
        "description": "按字段分级脱敏，默认掩码；敏感字段取原文需显式申请并记录例外。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "records": {"type": "array", "items": {"type": "object"}},
                "actor_id": {"type": "string"},
                "actor_role": {"type": "string", "enum": list(FORM_MATRIX)},
                "request_raw": {"type": "boolean", "default": False},
                "data_source": {"type": "string"},
            },
            "required": ["records"],
        },
        "fn": tool_deidentify,
    },
    "lb_normalize": {
        "description": "ASTM 记录或 OCR 结构归一化为统一结果模型。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "raw_records": {"type": "array", "items": {"type": "object"}},
                "actor_id": {"type": "string"},
                "data_source": {"type": "string"},
            },
            "required": ["raw_records"],
        },
        "fn": tool_normalize,
    },
    "lb_screen": {
        "description": "最小审核规则引擎：异常标志聚合 / 危急值预筛 / 趋势漂移。只输出待关注列表。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "results": {"type": "array", "items": {"type": "object"}},
                "window_days": {"type": "integer", "default": 7},
                "drift_pct": {"type": "number", "default": 30},
                "actor_id": {"type": "string"},
            },
            "required": ["results"],
        },
        "fn": tool_screen,
    },
    "lb_check_wording": {
        "description": "检查输出措辞是否触碰禁用表述（已审核/已签发/结论为/诊断）。",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
        "fn": tool_check_wording,
    },
    "lb_evidence_pack": {
        "description": "生成证据包目录骨架与 manifest.json（含哈希与时间戳）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output_dir": {"type": "string", "default": "evidence_pack"},
                "stage": {"type": "string", "default": "demo"},
                "actor_id": {"type": "string"},
            },
        },
        "fn": tool_evidence_pack,
    },
}


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 / stdio 传输（依据 MCP 公开行为规范重写）
# ---------------------------------------------------------------------------

def _tools_list() -> List[Dict[str, Any]]:
    return [
        {"name": n, "description": t["description"], "inputSchema": t["inputSchema"]}
        for n, t in TOOLS.items()
    ]


def handle_request(req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method = req.get("method")
    rid = req.get("id")
    params = req.get("params") or {}

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO,
        }}
    if method == "notifications/initialized" or (method or "").startswith("notifications/"):
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": _tools_list()}}
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        tool = TOOLS.get(name)
        if not tool:
            return {"jsonrpc": "2.0", "id": rid, "error":
                    {"code": -32601, "message": f"unknown tool: {name}"}}
        try:
            out = tool["fn"](args)
        except Exception as e:  # 工具内部异常不瘫痪整个 server
            return {"jsonrpc": "2.0", "id": rid, "error":
                    {"code": -32603, "message": f"tool error: {e}"}}
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text",
                         "text": json.dumps(out, ensure_ascii=False, indent=2)}],
            "isError": False,
        }}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    return {"jsonrpc": "2.0", "id": rid, "error":
            {"code": -32601, "message": f"method not found: {method}"}}


def serve_stdio() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle_request(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------

def selftest() -> int:
    print("== LabBridge MCP Server 自检 ==")
    ok = True

    r0 = handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    ok &= r0["result"]["serverInfo"]["name"] == "labbridge"
    print(f"[1] initialize -> protocolVersion={r0['result']['protocolVersion']}")

    r1 = handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = [t["name"] for t in r1["result"]["tools"]]
    print(f"[2] tools/list -> {names}")
    ok &= set(names) == set(TOOLS)

    recs = [{"patient_id": "P001", "patient_name": "张三", "phone": "13800138000",
             "test_item": "K", "result_value": 7.2, "abnormal_flag": "H"}]
    r2 = handle_request({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": "lb_deidentify",
                                    "arguments": {"records": recs, "actor_id": "u1",
                                                  "actor_role": "technician"}}})
    out2 = json.loads(r2["result"]["content"][0]["text"])
    print(f"[3] deidentify -> {json.dumps(out2['records'], ensure_ascii=False)}")
    ok &= out2["deidentify_ok"] and "patient_name" not in out2["records"][0]

    r3 = handle_request({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                         "params": {"name": "lb_screen",
                                    "arguments": {"results": [
                                        {"patient_pseudo_id": "P001", "test_item": "K",
                                         "result_value": 7.2, "abnormal_flag": "H"},
                                        {"patient_pseudo_id": "P001", "test_item": "K",
                                         "result_value": 4.0, "abnormal_flag": ""},
                                    ], "actor_id": "u1"}}})
    out3 = json.loads(r3["result"]["content"][0]["text"])
    print(f"[4] screen -> {out3['count']} flags, urgent={out3['urgent_count']}")
    ok &= out3["count"] >= 2

    r4 = handle_request({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                         "params": {"name": "lb_check_wording",
                                    "arguments": {"text": "本报告已审核通过"}}})
    print(f"[5] wording -> compliant={json.loads(r4['result']['content'][0]['text'])['compliant']}")
    ok &= not json.loads(r4["result"]["content"][0]["text"])["compliant"]

    print(f"[6] audit events recorded: {len(AUDIT_LOG)}")
    ok &= len(AUDIT_LOG) >= 3
    if AUDIT_LOG:
        print(f"    样例: {json.dumps(AUDIT_LOG[-1], ensure_ascii=False)[:160]}...")

    print("\n结果:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    serve_stdio()
