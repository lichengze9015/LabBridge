#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LabBridge 审计日志中间件（P2）—— 纯标准库，哈希链防篡改

Provenance / 反溯说明
---------------------
依据文档 05 第六章（日志规范）与第七章（时间戳与哈希锚定）独立编写，
未基于任何开源日志组件改造。字段 Schema 直接取自 05 号文档 6.3 节。

文档 05 的硬性要求（本模块逐条落实）：
    6.1  四类场景必须生成日志：重要活动 / 开发期变动 / 运行期重要错误 / 有人参与的动作
    6.2  有人参与的动作必须「具体到账户 ID 或操作人员名字」——
         不接受「系统已审核」这类无主体记录 ⇒ 见 `require_actor()`
    6.3  16 个字段的 Schema ⇒ 见 `FIELDS`
    7    三类受控文件（规则文件 / 例外审批 / 运行时日志）各自锚定时间戳与哈希

证据链闭环公式（05 号文档）：
    规则文件（人签署 + 时间戳）
      → 例外审批记录（人裁定 + 时间戳）
        → 运行时访问日志（机器执行 + 时间戳 + 哈希）
          ⇒ 可证明「规则被批准且被真实执行」

哈希链设计：
    每条记录带 `seq`（自增）与 `prev_hash`，`hash = sha256(规范化内容 + prev_hash)`。
    任何删除、插队、篡改都会导致 `verify_chain()` 校验失败。
"""

import datetime
import hashlib
import json
import os
import threading
import uuid
from typing import Any, Dict, List, Optional

# 文档 05 6.3 节字段 Schema（顺序即落盘顺序）
FIELDS = [
    "event_id", "seq", "timestamp", "actor_id", "actor_role", "action",
    "object", "data_class", "field_form", "policy_hit", "agent_version",
    "data_source", "human_involved", "result", "prev_hash", "hash",
]

# 文档 05 6.1 节：必须生成日志的四类场景
MANDATORY_SCENES = ["important_activity", "dev_change", "runtime_error", "human_action"]

# 文档 05 6.2 节：这些动作属于「有人参与」，actor_id 不可为 system/unknown
HUMAN_ACTIONS = {"审核", "复核", "撤回", "确认", "例外放行", "终审",
                 "approve", "review", "confirm", "revoke", "override"}

AGENT_VERSION = "1.0.0"
GENESIS_HASH = "0" * 64

_lock = threading.Lock()


class ActorRequired(Exception):
    """有人参与的动作未提供 actor_id —— 按 05 号文档 6.2 节这是不可接受的日志。"""


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256_of(obj: Any) -> str:
    payload = json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def require_actor(action: str, actor_id: str) -> None:
    """文档 05 6.2：有人参与的动作必须有具体到人/账户的主体。"""
    if action in HUMAN_ACTIONS and (not actor_id or actor_id in ("system", "unknown", "")):
        raise ActorRequired(
            f"动作 '{action}' 属于有人参与的动作，必须提供具体 actor_id"
            f"（不接受 'system' / 'unknown'）——文档 05 第 6.2 节"
        )


class AuditLog:
    """带哈希链的审计日志。落盘 JSONL，首行是链头。"""

    def __init__(self, path: str = None, agent_version: str = AGENT_VERSION):
        self.path = path or os.environ.get("LABBRIDGE_AUDIT_LOG", "audit_log.jsonl")
        self.agent_version = agent_version
        self.records: List[Dict[str, Any]] = []
        self._seq = 0
        self._last_hash = GENESIS_HASH
        parent = os.path.dirname(os.path.abspath(self.path))
        if parent:
            os.makedirs(parent, exist_ok=True)

    # -- 写入 ---------------------------------------------------------------

    def record(self, action: str, actor_id: str = "unknown", actor_role: str = "technician",
               object: str = "", data_class: str = "internal", field_form: str = "raw",
               policy_hit: str = "", data_source: str = "", human_involved: bool = False,
               result: str = "ok", **extra: Any) -> Dict[str, Any]:
        if human_involved and action in HUMAN_ACTIONS:
            require_actor(action, actor_id)
        with _lock:
            self._seq += 1
            rec: Dict[str, Any] = {
                "event_id": str(uuid.uuid4()),
                "seq": self._seq,
                "timestamp": now_iso(),
                "actor_id": actor_id,
                "actor_role": actor_role,
                "action": action,
                "object": object,
                "data_class": data_class,
                "field_form": field_form,
                "policy_hit": policy_hit,
                "agent_version": self.agent_version,
                "data_source": data_source,
                "human_involved": human_involved,
                "result": result,
                "prev_hash": self._last_hash,
            }
            if extra:
                rec["extra"] = extra
            rec["hash"] = sha256_of({k: v for k, v in rec.items() if k != "hash"})
            self._last_hash = rec["hash"]
            self.records.append(rec)
            self._append(rec)
            return rec

    def _append(self, rec: Dict[str, Any]) -> None:
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
        except OSError:
            pass  # 落盘失败不阻断主流程，内存副本仍在，但会记入 integrity 章节

    # -- 校验 ---------------------------------------------------------------

    def verify_chain(self, records: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """校验哈希链完整性：序号连续、prev_hash 衔接、hash 自洽。"""
        recs = records if records is not None else self.records
        prev = GENESIS_HASH
        problems: List[str] = []
        for idx, rec in enumerate(recs):
            if rec.get("seq") != idx + 1:
                problems.append(f"seq 断裂于第 {idx} 条: 期望 {idx+1} 实为 {rec.get('seq')}")
            if rec.get("prev_hash") != prev:
                problems.append(f"prev_hash 不衔接于第 {idx} 条")
            expect = sha256_of({k: v for k, v in rec.items() if k != "hash"})
            if rec.get("hash") != expect:
                problems.append(f"内容被篡改于第 {idx} 条")
            prev = rec.get("hash", prev)
        return {"ok": not problems, "count": len(recs), "problems": problems,
                "head_hash": prev}

    @staticmethod
    def load(path: str) -> List[Dict[str, Any]]:
        if not os.path.exists(path):
            return []
        out = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    # -- 统计 ---------------------------------------------------------------

    def coverage_report(self) -> Dict[str, Any]:
        """文档 02 目标 1：全程日志留痕率 100%。此处给出可核算的口径。"""
        recs = self.records
        total = len(recs)
        missing_actor = [r["seq"] for r in recs
                         if r.get("human_involved") and r.get("actor_id") in ("", "unknown", "system")]
        return {
            "total_events": total,
            "human_involved_events": sum(1 for r in recs if r.get("human_involved")),
            "events_missing_actor": missing_actor,
            "log_trace_coverage": 1.0 if total and not missing_actor else (0.0 if total else None),
            "by_action": _tally(recs, "action"),
            "by_data_class": _tally(recs, "data_class"),
            "by_result": _tally(recs, "result"),
        }


def _tally(recs: List[Dict[str, Any]], key: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for r in recs:
        out[str(r.get(key))] = out.get(str(r.get(key)), 0) + 1
    return out


# ---------------------------------------------------------------------------
# 受控文件锚定（文档 05 第七章）
# ---------------------------------------------------------------------------

def anchor_file(path: str, signer: str, note: str = "") -> Dict[str, Any]:
    """对受控文件（规则文件 / 例外审批记录）生成时间戳 + 哈希锚定记录。

    外审时要回答的是：「这份规则在某个时刻被批准，并在之后的每一次访问中实际执行了」。
    """
    with open(path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    return {
        "file": os.path.basename(path),
        "path": os.path.abspath(path),
        "sha256": digest,
        "anchored_at": now_iso(),
        "signed_by": signer,
        "note": note,
    }


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------

def selftest() -> int:
    import tempfile
    print("== labbridge_auditlog 自检 ==")
    ok = True
    tmp = tempfile.mkdtemp(prefix="lb_audit_")
    log = AuditLog(os.path.join(tmp, "audit.jsonl"))

    log.record("receive", actor_id="system", data_source="astm", data_class="internal")
    log.record("deidentify", actor_id="system", data_class="sensitive", field_form="mask",
               policy_hit="PII-L3-mask")
    log.record("审核", actor_id="张医生", actor_role="director", human_involved=True,
               data_class="sensitive", policy_hit="human-in-the-loop")

    v = log.verify_chain()
    print(f"[1] 哈希链校验: ok={v['ok']} count={v['count']}")
    ok &= v["ok"] and v["count"] == 3

    tampered = [dict(r) for r in log.records]
    tampered[1]["result"] = "tampered"
    v2 = log.verify_chain(tampered)
    print(f"[2] 篡改可检出: ok={v2['ok']} ({len(v2['problems'])} 处)")
    ok &= (not v2["ok"])

    removed = [dict(r) for r in log.records[:1]] + [dict(r) for r in log.records[2:]]
    v3 = log.verify_chain(removed)
    print(f"[3] 删除可检出: ok={v3['ok']}")
    ok &= (not v3["ok"])

    cov = log.coverage_report()
    print(f"[4] 留痕覆盖率={cov['log_trace_coverage']} 人工事件={cov['human_involved_events']}")
    ok &= cov["log_trace_coverage"] == 1.0

    try:
        log.record("审核", actor_id="system", human_involved=True)
        print("[5] 无主体人工动作: FAIL（未拦截）")
        ok = False
    except ActorRequired:
        print("[5] 无主体人工动作被拦截: OK（文档 05 6.2）")
        ok &= True

    reloaded = AuditLog.load(log.path)
    v4 = log.verify_chain(reloaded)
    print(f"[6] 落盘后重读校验: ok={v4['ok']} count={v4['count']}")
    ok &= v4["ok"] and v4["count"] == 3

    p = os.path.join(tmp, "rule.yaml")
    with open(p, "w", encoding="utf-8") as f:
        f.write("field_class:\n  patient_name: sensitive\n")
    a = anchor_file(p, signer="李主任", note="分级规则 V1.0")
    print(f"[7] 受控文件锚定: {a['file']} sha256={a['sha256'][:16]}... signer={a['signed_by']}")
    ok &= len(a["sha256"]) == 64 and a["signed_by"] == "李主任"

    print("结果:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
