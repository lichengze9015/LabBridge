#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LabBridge 红线自检 · 阶段门 · 审批门 —— 纯标准库

Provenance / 反溯说明
---------------------
依据文档 02 第五节（项目红线）、文档 05 第八章（人在回路审计）、
文档 06（实施流程与阶段门）、文档 02 的 `stage_gate` 建议独立编写。
社区无对应可封包资产——这是本项目的方法论内核，属自研。

三条不可协商的机制：

1. **红线自检**（文档 02 第五节）
   启动敏感数据处理前逐条自检，任一不满足则拒绝启动。

2. **阶段门**（文档 02 第四节）
   阶段三「风险评估通过」是阶段四的前置条件，未过则工作流阻塞。
   「顺序即红线」——这句不是口号，是这个模块的一条 if。

3. **审批门**（文档 05 8.2）
   审批不能只弹「是否执行」，必须携带四要素：
   动作计划 / 预期影响 / 风险提示 / 回滚方案。
   **审批超时默认拒绝**，避免无人值守时高风险操作被放行。
"""

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from labbridge_config import Config, config_path

# 文档 02 第五节：项目红线（核心约束，不可协商）
REDLINES = [
    ("R-1", "敏感数据必须等风险控制措施部署评审完成后才可接入，禁止提前加载"),
    ("R-2", "无论何种模型处理敏感数据，坚持人在回路，高风险判定、最终结论由人终审"),
    ("R-3", "全程留痕：数据导入、模型调用、输出、人工修订均须时间戳、操作员、版本记录"),
    ("R-4", "Demo 敏感场景结论可作正式项目决策依据，但 Demo 本身不等于生产级上线系统"),
    ("R-5", "单个试点验收完成后扩大应用范围，必须重新独立立项、新建 POC"),
]


class GateError(Exception):
    """门禁未通过。"""


# ---------------------------------------------------------------------------
# 1. 红线自检
# ---------------------------------------------------------------------------

class RedlineCheck:
    """启动敏感数据处理前的红线自检。"""

    def __init__(self, log=None) -> None:
        self.log = log
        self.evidence: Dict[str, Any] = {}

    def check(self, risk_assessment_approved: bool = False,
              control_measures_deployed: bool = False,
              human_review_enabled: bool = True,
              audit_log_enabled: bool = True,
              production_claim: bool = False) -> Dict[str, Any]:
        results = [
            ("R-1", risk_assessment_approved and control_measures_deployed,
             "风险评估已批准 且 控制措施已部署评审通过"),
            ("R-2", human_review_enabled, "人在回路已启用，高风险判定由人终审"),
            ("R-3", audit_log_enabled, "审计日志已启用，全程留痕"),
            ("R-4", not production_claim, "未宣称本 Demo 为生产级上线系统"),
            ("R-5", True, "扩容须重新独立立项（流程约束，运行时恒真）"),
        ]
        failed = [rid for rid, ok, _ in results if not ok]
        verdict = {
            "passed": not failed,
            "failed": failed,
            "details": [{"id": rid, "ok": ok, "desc": d} for rid, ok, d in results],
            "checked_at": time.time(),
        }
        if self.log:
            # 系统自检动作：主体就是 system，不构成「有人参与的动作」
            self.log.record("redline_check", actor_id="system",
                            object="startup self-check",
                            result="pass" if verdict["passed"] else f"blocked:{failed}",
                            human_involved=False)
        return verdict

    def require(self, **kw: Any) -> Dict[str, Any]:
        v = self.check(**kw)
        if not v["passed"]:
            raise GateError(f"红线自检未通过，拒绝启动敏感数据处理：{v['failed']}")
        return v


# ---------------------------------------------------------------------------
# 2. 阶段门（文档 02 第四节：顺序即红线）
# ---------------------------------------------------------------------------

class StageGate:
    """四阶段顺序门。阶段三未通过评审，阶段四不得加载敏感数据。"""

    def __init__(self, config: Optional[Config] = None, log=None,
                 state_path: str = None) -> None:
        self.cfg = config or Config()
        self.log = log
        self.state_path = state_path or os.environ.get(
            "LABBRIDGE_GATE_STATE", config_path("gate_state.json"))
        self.state: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        if os.path.exists(self.state_path):
            try:
                with open(self.state_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (OSError, json.JSONDecodeError):
                pass
        return {"approved": {}, "history": []}

    def save(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.state_path)), exist_ok=True)
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(self.state, f, ensure_ascii=False, indent=2)

    def approve(self, requirement: str, approver: str, note: str = "") -> None:
        """人审批通过某个前置条件。approver 必须是具体的人/账户 ID。"""
        if not approver or approver in ("system", "unknown"):
            raise GateError("审批人必须是具体的人或账户 ID（文档 05 6.2）")
        from labbridge_auditlog import now_iso
        self.state["approved"][requirement] = {
            "approver": approver, "at": now_iso(), "note": note}
        self.state["history"].append({"requirement": requirement,
                                      "approver": approver, "at": now_iso()})
        self.save()
        if self.log:
            self.log.record("确认", actor_id=approver, actor_role="director",
                            object=requirement, human_involved=True,
                            result="approved", extra={"note": note})

    def can_load_sensitive(self) -> Dict[str, Any]:
        gate = (self.cfg.stage_gate or {}).get("sensitive_data_load", {})
        requires = gate.get("requires", ["risk_assessment_approved",
                                         "control_measures_deployed"])
        missing = [r for r in requires if r not in self.state["approved"]]
        verdict = {"allowed": not missing, "requires": requires, "missing": missing,
                   "approved": dict(self.state["approved"])}
        if missing and self.log:
            self.log.record("stage_gate", actor_id="system",
                            object="sensitive_data_load", result="blocked",
                            human_involved=False, extra={"missing": missing})
        return verdict

    def require_sensitive(self) -> None:
        v = self.can_load_sensitive()
        if not v["allowed"]:
            raise GateError(
                f"阶段门未放行，禁止加载敏感数据。缺失前置条件：{v['missing']}"
                f"（文档 02：阶段三评审未通过，不得进入阶段四）")


# ---------------------------------------------------------------------------
# 3. 审批门（文档 05 第八章）
# ---------------------------------------------------------------------------

@dataclass
class ApprovalRequest:
    """审批卡必须携带的四要素（文档 05 8.2）。缺一不可。"""
    action_plan: str        # 动作计划：要做什么
    expected_impact: str    # 预期影响：影响什么
    risk_note: str          # 风险提示：可能出什么问题
    rollback_plan: str      # 回滚方案：出问题怎么撤回
    risk_level: str = "high"   # low / medium / high
    requester: str = "system"
    extra: Dict[str, Any] = field(default_factory=dict)

    def missing(self) -> List[str]:
        miss = []
        for k, label in (("action_plan", "动作计划"), ("expected_impact", "预期影响"),
                         ("risk_note", "风险提示"), ("rollback_plan", "回滚方案")):
            if not (getattr(self, k) or "").strip():
                miss.append(label)
        return miss

    def as_dict(self) -> Dict[str, Any]:
        return {"action_plan": self.action_plan, "expected_impact": self.expected_impact,
                "risk_note": self.risk_note, "rollback_plan": self.rollback_plan,
                "risk_level": self.risk_level, "requester": self.requester,
                "missing_elements": self.missing(), **self.extra}


class ApprovalGate:
    """高风险动作的审批门。

    策略（文档 05 8.1）：
        low     → 自动执行 + 事后抽样审计
        medium  → 触发人工审批
        high    → 强制人工审批，禁止全自动
    审批超时默认拒绝（文档 05 8.2）。
    """

    DEFAULT_TIMEOUT_SEC = 300

    def __init__(self, log=None, timeout_sec: int = None) -> None:
        self.log = log
        self.timeout = timeout_sec or int(
            os.environ.get("LABBRIDGE_APPROVAL_TIMEOUT", self.DEFAULT_TIMEOUT_SEC))

    def evaluate(self, req: ApprovalRequest) -> Dict[str, Any]:
        """判定该动作需要走哪条回路。"""
        miss = req.missing()
        if miss:
            return {"mode": "rejected", "reason": f"审批卡缺少必备要素：{miss}",
                    "request": req.as_dict()}
        level = (req.risk_level or "high").lower()
        if level == "low":
            mode = "auto_with_sampling"
        elif level == "medium":
            mode = "require_approval"
        else:
            mode = "require_approval_block_auto"
        if self.log:
            self.log.record("approval_eval", actor_id=req.requester,
                            object=req.action_plan[:60], result=mode,
                            human_involved=False, extra={"risk_level": level})
        return {"mode": mode, "request": req.as_dict()}

    def wait_decision(self, req: ApprovalRequest,
                      ask: Callable[[ApprovalRequest], Optional[bool]] = None,
                      timeout_sec: int = None) -> Dict[str, Any]:
        """等待人工裁定。`ask` 为获取裁定的回调，返回 True/False/None(未决)。

        超时或回调返回 None → **默认拒绝**（文档 05 8.2）。
        """
        ev = self.evaluate(req)
        if ev["mode"] == "rejected":
            return {**ev, "decision": "rejected", "reason": ev["reason"]}
        if ev["mode"] == "auto_with_sampling":
            return {**ev, "decision": "auto_approved", "note": "低风险：自动执行，事后抽样审计"}

        limit = timeout_sec if timeout_sec is not None else self.timeout
        deadline = time.time() + limit
        answer = ask(req) if ask else None
        while answer is None and time.time() < deadline:
            time.sleep(min(0.5, max(0.0, deadline - time.time())))
            answer = ask(req) if ask else None

        decided = bool(answer)
        if self.log:
            self.log.record("审核", actor_id=req.requester, object=req.action_plan[:60],
                            result="approved" if decided else "timeout_denied",
                            human_involved=True,
                            extra={"waited_sec": round(limit - max(0.0, deadline - time.time()), 1)})
        return {**ev, "decision": "approved" if decided else "rejected",
                "reason": None if decided else "审批超时默认拒绝（文档 05 8.2）"}


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------

def selftest() -> int:
    import tempfile
    print("== labbridge_gate 自检 ==")
    ok = True

    rl = RedlineCheck()
    bad = rl.check(risk_assessment_approved=False, control_measures_deployed=True)
    print(f"[1] 红线未满足: passed={bad['passed']} failed={bad['failed']}")
    ok &= (not bad["passed"]) and "R-1" in bad["failed"]

    good = rl.check(risk_assessment_approved=True, control_measures_deployed=True)
    print(f"[2] 红线全满足: passed={good['passed']}")
    ok &= good["passed"]

    try:
        rl.require(risk_assessment_approved=False)
        print("[3] 红线阻断: FAIL（未拦截）"); ok = False
    except GateError:
        print("[3] 红线阻断: OK"); ok &= True

    # 阶段门
    tmp = tempfile.mkdtemp(prefix="lb_gate_")
    sg = StageGate(state_path=os.path.join(tmp, "gate_state.json"))
    v0 = sg.can_load_sensitive()
    print(f"[4] 阶段门（未审批）: allowed={v0['allowed']} missing={v0['missing']}")
    ok &= (not v0["allowed"])

    try:
        sg.require_sensitive()
        print("[5] 敏感数据加载阻断: FAIL（未拦截）"); ok = False
    except GateError:
        print("[5] 敏感数据加载阻断: OK"); ok &= True

    try:
        sg.approve("risk_assessment_approved", "system")
        print("[6] 无主体审批: FAIL（未拦截）"); ok = False
    except GateError:
        print("[6] 无主体审批被拦截: OK（文档 05 6.2）"); ok &= True

    sg.approve("risk_assessment_approved", "李主任", note="阶段三评审通过")
    sg.approve("control_measures_deployed", "李主任", note="控制措施部署评审通过")
    v1 = sg.can_load_sensitive()
    print(f"[7] 阶段门（已审批）: allowed={v1['allowed']}")
    ok &= v1["allowed"]

    # 审批门四要素
    ag = ApprovalGate(timeout_sec=2)
    incomplete = ApprovalRequest(action_plan="回写 LIS", expected_impact="",
                                 risk_note="可能写错", rollback_plan="")
    e1 = ag.evaluate(incomplete)
    print(f"[8] 缺要素审批卡: mode={e1['mode']} 缺={e1['request']['missing_elements']}")
    ok &= e1["mode"] == "rejected" and len(e1["request"]["missing_elements"]) == 2

    full = ApprovalRequest(action_plan="回写 LIS", expected_impact="写入 128 条结果",
                           risk_note="字段映射错误导致结果错位",
                           rollback_plan="保留写前快照，一键回滚并留痕",
                           risk_level="high", requester="张工")
    e2 = ag.evaluate(full)
    print(f"[9] 高风险: mode={e2['mode']}")
    ok &= e2["mode"] == "require_approval_block_auto"

    d_timeout = ag.wait_decision(full, ask=lambda r: None)
    print(f"[10] 超时默认拒绝: decision={d_timeout['decision']}")
    ok &= d_timeout["decision"] == "rejected"

    d_ok = ag.wait_decision(full, ask=lambda r: True)
    print(f"[11] 人工批准: decision={d_ok['decision']}")
    ok &= d_ok["decision"] == "approved"

    low = ApprovalRequest(action_plan="查询脱敏结果", expected_impact="只读",
                          risk_note="无", rollback_plan="无需回滚", risk_level="low")
    d_low = ag.wait_decision(low)
    print(f"[12] 低风险自动执行: decision={d_low['decision']}")
    ok &= d_low["decision"] == "auto_approved"

    print("结果:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
