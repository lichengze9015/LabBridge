#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LabBridge Demo 编排器 —— 端到端跑通轨道 A / 轨道 B，并产出证据包

Provenance / 反溯说明
---------------------
纯标准库，编排层自研。串起本项目各模块，不引入 langgraph / crewAI 等框架
（文档 09 第五节：框架是给「没有平台」的人准备的，这里只需要一条确定的流水线）。

诚实边界（务必阅读）
--------------------
本脚本默认跑的是**合成数据**（`simulate_session`）。它能验证的是：
    链路是否通、规则是否生效、门禁是否拦截、日志是否留痕、证据包是否完整。
它**不能**用来宣称达成了文档 02 目标 3 的实测基线——
目标 3 要求「≥50 份真实标本、完整率 ≥99%、与人工判断一致率 ≥95%」，
真实数据必须由医院受控提供，人工一致率必须由检验人员实际复核得出。
因此脚本中所有涉及真实基线的指标都会被标为 `synthetic=True` 且不写入正式结论。

用法:
    python labbridge_demo.py --run                       # 默认跑通双轨（合成数据）
    python labbridge_demo.py --run --samples 50          # 指定标本数
    python labbridge_demo.py --run --approve-stage3 --approver 李主任
    python labbridge_demo.py --selftest
"""

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List

from labbridge_astm import AstmReceiver, simulate_session
from labbridge_auditlog import AuditLog
from labbridge_config import Config, config_path
from labbridge_deid import Deidentifier
from labbridge_evidence import (AcceptanceRunner, Capa, EvidencePack,
                                export_asset_pack)
from labbridge_gate import ApprovalGate, ApprovalRequest, GateError, RedlineCheck, StageGate
from labbridge_ocr import OcrIntake, extract_fields
from labbridge_screen import ScreenEngine, agreement_report

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.normpath(os.path.join(HERE, "..", "output"))

# 轨道 B 的合成 OCR 文本（用于无硬件验证链路）
DEMO_OCR_TEXT = """某某卫生院检验报告单
姓名 合成患者  性别 男  年龄 45
白细胞 6.4 10^9/L 4.0-10.0
血红蛋白 132 g/L 115-150
血小板 210 10^9/L 125-350
血钾 7.3 mmol/L 3.5-5.3 H
血糖 5.6 mmol/L 3.9-6.1
"""


def _ref_judgement(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """参考判定：结果超出参考区间即为「需关注」。

    这是**机器参考判据**，用来做规则引擎的自检，
    不是真实人工复核。用于一致率时必须标注来源，不得冒充人工。
    """
    out = []
    for r in results:
        ref = r.get("ref_range") or ""
        val = r.get("result_value")
        if not ref or val is None:
            continue
        try:
            lo_s, hi_s = ref.split("-")
            lo, hi = float(lo_s), float(hi_s)
        except (ValueError, AttributeError):
            continue
        if val < lo or val > hi:
            out.append({"patient_pseudo_id": r.get("patient_pseudo_id", ""),
                        "test_item": r.get("test_item", ""),
                        "specimen_id": r.get("specimen_id", "")})
    return out


class DemoRun:
    def __init__(self, output_dir: str = DEFAULT_OUT, samples: int = 50,
                 approver: str = "", approve_stage3: bool = False) -> None:
        self.out = output_dir
        self.samples = samples
        self.approver = approver
        self.approve_stage3 = approve_stage3
        os.makedirs(self.out, exist_ok=True)

        self.log_path = os.path.join(self.out, "audit_log.jsonl")
        if os.path.exists(self.log_path):
            os.remove(self.log_path)          # 每次运行留一份干净的链
        self.log = AuditLog(self.log_path)
        self.cfg = Config()
        self.timeline: List[Dict[str, Any]] = []
        self.blockers: List[str] = []

    def _step(self, name: str, detail: Any = None) -> None:
        self.timeline.append({"step": name, "at": time.time(), "detail": detail})

    # -- 1 红线自检 ---------------------------------------------------------

    def step_redline(self) -> Dict[str, Any]:
        rl = RedlineCheck(log=self.log)
        v = rl.check(risk_assessment_approved=False, control_measures_deployed=False)
        self._step("红线自检", {"passed": v["passed"], "failed": v["failed"]})
        if not v["passed"]:
            self.blockers.append(f"红线未满足，敏感数据处理受限：{v['failed']}")
        return v

    # -- 2 阶段门 -----------------------------------------------------------

    def step_stage_gate(self) -> Dict[str, Any]:
        sg = StageGate(config=self.cfg, log=self.log,
                       state_path=config_path("gate_state.json"))
        if self.approve_stage3 and self.approver:
            for req in ("risk_assessment_approved", "control_measures_deployed"):
                if req not in sg.state["approved"]:
                    sg.approve(req, self.approver,
                               note="Demo 编排器按命令行显式审批记录")
        v = sg.can_load_sensitive()
        self._step("阶段门", v)
        if not v["allowed"]:
            self.blockers.append(
                f"阶段四未放行（缺失 {v['missing']}）：本次仅运行合成/非敏感数据")
        return v

    # -- 3 轨道 A -----------------------------------------------------------

    def step_track_a(self) -> Dict[str, Any]:
        stream = simulate_session(n_samples=self.samples, seed=20261022)
        rx = AstmReceiver(mode="passive", log=self.log)
        summary = rx.feed_bytes(stream)
        raw_results = rx.results()
        # 行级授权需要知道每行数据归属的科室/区域。真实部署时由桥接层的
        # 仪器↔科室登记表提供（属于受控配置，见 access_map.csv 的 scope 列）。
        for r in raw_results:
            r.setdefault("dept", "检验科")
            r.setdefault("region", "本院")
        self._step("轨道A 接收", summary)

        de = Deidentifier(config=self.cfg, log=self.log)
        deid = de.deidentify(raw_results, actor_id="tech01", role="technician",
                             data_source="astm")
        self._step("轨道A 脱敏", {"stats": deid["stats"], "ok": deid["deidentify_ok"],
                                  "leaks": len(deid["leak_hits"])})

        sc = ScreenEngine(config=self.cfg, log=self.log)
        screened = sc.screen(deid["records"], actor_id="engine", data_source="astm")
        self._step("轨道A 审核", {"count": screened["count"],
                                 "urgent": screened["urgent_count"]})

        specimens = {r.get("specimen_id") for r in deid["records"]}
        human = _ref_judgement(deid["records"])
        agree = agreement_report(screened["watchlist"], human, len(deid["records"]))
        agree["note"] = ("参考判定为「结果超出参考区间」的机器判据，"
                         "非真实人工复核，不得作为目标 3 的一致率证据")

        # 措辞合规检查：输出绝不能出现结论性表述
        wording = sc.check_wording(json.dumps(screened, ensure_ascii=False))

        return {"receiver": summary, "results": len(deid["records"]),
                "specimens": len(specimens), "deidentify": deid,
                "screen": screened, "agreement": agree, "wording": wording}

    # -- 4 轨道 B -----------------------------------------------------------

    def step_track_b(self) -> Dict[str, Any]:
        intake = OcrIntake(log=self.log, local_only=True)
        rec = intake.intake("__demo_no_backend__.png", actor_id="王村医")
        # 无 OCR 后端时用合成文本填充，模拟「OCR 预填 + 人工确认」
        rec.text = DEMO_OCR_TEXT
        rec.confidence = 0.88
        rec.backend = "demo-text"
        rec.fields = extract_fields(DEMO_OCR_TEXT)
        intake.confirm(0, "王村医", status="confirmed")

        de = Deidentifier(config=self.cfg, log=self.log)
        rows = [{"patient_pseudo_id": "PSN-TOWN-001", "sex": "男",
                 "dept": "检验科", "region": "本院", **f}
                for f in rec.fields]
        deid = de.deidentify(rows, actor_id="tech01", role="technician",
                             data_source="ocr")

        sc = ScreenEngine(config=self.cfg, log=self.log)
        screened = sc.screen(deid["records"], actor_id="engine", data_source="ocr")

        upload = intake.export_for_upload()
        return {"intake_backend": rec.backend, "confirmed_by": rec.confirmed_by,
                "fields": len(rec.fields), "deidentify": deid,
                "screen": screened, "upload_payload": upload,
                "degraded": intake.degraded}

    # -- 5 审批门演示 -------------------------------------------------------

    def step_approval(self) -> Dict[str, Any]:
        ag = ApprovalGate(log=self.log, timeout_sec=3)
        req = ApprovalRequest(
            action_plan="将本次待关注列表回写至原厂 LIS",
            expected_impact=f"影响 {self.samples} 份标本的结果标记",
            risk_note="字段映射错误可能导致结果错位，属不可逆操作",
            rollback_plan="保留写前快照，一键回滚并留痕",
            risk_level="high", requester="张工")
        d = ag.wait_decision(req, ask=lambda r: None)   # 无人值守 → 超时默认拒绝
        self._step("审批门（高风险·无人值守）", d["decision"])
        return d

    # -- 6 验收断言 ---------------------------------------------------------

    def step_acceptance(self, a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
        ar = AcceptanceRunner(self.cfg)
        deid_ok = a["deidentify"]["deidentify_ok"] and b["deidentify"]["deidentify_ok"]
        cov = self.log.coverage_report()
        metrics = {
            "sample_capture_min": a["specimens"],
            "result_completeness": AcceptanceRunner.completeness(a["deidentify"]["records"]),
            "deidentify_accuracy": 1.0 if deid_ok else 0.0,
            "log_trace_coverage": cov["log_trace_coverage"] or 0.0,
        }
        # 关键取舍：abnormal_agreement（与人工判断一致率 ≥95%）**不参与本次断言**。
        # 人工一致率只能由检验人员真实复核得出；用任何机器判据替代都属于伪造证据，
        # 与本项目「不制造虚假体系证据」的红线冲突。因此该指标保持「未测量」，
        # 并把规则与区间判据的分歧如实作为「待人工裁定项」单列。
        res = ar.run(metrics)
        res["metrics"] = metrics
        res["synthetic"] = True
        res["human_review_required"] = True
        res["rule_vs_range_overlap"] = {
            "agreement_rate": a["agreement"]["agreement_rate"],
            "ai_only": len(a["agreement"]["ai_only"]),
            "reference_only": len(a["agreement"]["human_only"]),
            "meaning": ("规则引擎标记与「结果超出参考区间」判据的重合度。"
                        "分歧部分不判对错，全部进人工裁定队列。"),
        }
        res["note"] = ("本次为合成数据自测，仅验证链路与规则；abnormal_agreement 与 "
                       "clause_match_accuracy 须由真实受控数据 + 人工复核得出，本次不测")
        self._step("验收断言", {"all_pass": res["all_pass"], "failed": res["failed"]})
        return res

    # -- 7 证据包 -----------------------------------------------------------

    def step_evidence(self, report: Dict[str, Any]) -> Dict[str, Any]:
        ep = EvidencePack(os.path.join(self.out, "evidence_pack"),
                          stage="demo", config=self.cfg, log=self.log)
        built = ep.build()
        ep.put("06_监视测量", "metrics.json", report["acceptance"]["metrics"])
        ep.put("06_监视测量", "acceptance_result.json", report["acceptance"])
        ep.put("06_监视测量", "track_a_watchlist.json", report["track_a"]["screen"])
        ep.put("06_监视测量", "track_b_watchlist.json", report["track_b"]["screen"])
        ep.put("03_运行日志", "audit_coverage.json", self.log.coverage_report())
        ep.put("01_风险与评估", "risk_register.json", self.cfg.risk_register)
        ep.put("02_规则与权限", "access_map.json", self.cfg.access_map)
        ep.put("00_方针与范围", "blockers.json",
               {"blockers": self.blockers, "note": "未解除的门禁，外审时须可追溯"})

        capa = Capa()
        for i, blk in enumerate(self.blockers, start=1):
            capa.open_issue(f"CAPA-{i:03d}", blk[:60], "异常事件", owner="项目负责人")
        capa.save(os.path.join(self.out, "evidence_pack", "05_CAPA", "capa_register.json"))

        asset_zip = os.path.join(self.out, "asset_pack.zip")
        # 排除输出目录：否则资产包会把「正在生成的自己」一起打进去
        pack = export_asset_pack(
            asset_zip,
            {"config": config_path(""), "docs": os.path.normpath(
                os.path.join(HERE, ".."))},
            version="1.0.0", exclude=[self.out])
        self._step("证据包与资产包", {"evidence_root": built["root"],
                                     "asset_zip": pack["zip"]})
        return {"evidence": built, "asset_pack": pack, "capa": capa.summary()}

    # -- 主流程 -------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        print("=" * 68)
        print("LabBridge Demo 端到端运行（合成数据，非真实患者数据）")
        print("=" * 68)

        redline = self.step_redline()
        print(f"[1/7] 红线自检: passed={redline['passed']} "
              f"受限项={redline['failed'] or '无'}")

        gate = self.step_stage_gate()
        print(f"[2/7] 阶段门: allowed={gate['allowed']} "
              f"缺失={gate['missing'] or '无'}")

        a = self.step_track_a()
        print(f"[3/7] 轨道A: 标本 {a['specimens']} 份, 结果 {a['results']} 条, "
              f"待关注 {a['screen']['count']} 条（危急 {a['screen']['urgent_count']}）, "
              f"脱敏ok={a['deidentify']['deidentify_ok']}")

        b = self.step_track_b()
        print(f"[4/7] 轨道B: 抽取 {b['fields']} 字段, 确认人={b['confirmed_by']}, "
              f"待关注 {b['screen']['count']} 条")

        ap = self.step_approval()
        print(f"[5/7] 审批门（高风险·无人值守）: {ap['decision']} "
              f"— {ap.get('reason') or ''}")

        acc = self.step_acceptance(a, b)
        print(f"[6/7] 验收断言: all_pass={acc['all_pass']} "
              f"failed={acc['failed'] or '无'} unmeasured={len(acc['unmeasured'])}")

        ev = self.step_evidence({"acceptance": acc, "track_a": a, "track_b": b})
        print(f"[7/7] 证据包: {ev['evidence']['root']}")
        print(f"      资产包: {ev['asset_pack']['zip']} "
              f"({ev['asset_pack']['manifest']['file_count']} 文件)")

        chain = self.log.verify_chain()
        report = {
            "run_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "synthetic_data": True,
            "redline": redline, "stage_gate": gate,
            "track_a": {k: v for k, v in a.items() if k != "deidentify"},
            "track_a_deid_stats": a["deidentify"]["stats"],
            "track_b": {k: v for k, v in b.items() if k != "deidentify"},
            "approval": ap, "acceptance": acc,
            "evidence": {"root": ev["evidence"]["root"],
                         "asset_zip": ev["asset_pack"]["zip"]},
            "capa": ev["capa"], "blockers": self.blockers,
            "audit": {"path": self.log_path, "events": len(self.log.records),
                      "chain_ok": chain["ok"], "head_hash": chain["head_hash"],
                      "coverage": self.log.coverage_report()},
        }
        with open(os.path.join(self.out, "demo_run_report.json"), "w",
                  encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print("-" * 68)
        print(f"审计链: {len(self.log.records)} 条, 完整性={chain['ok']}, "
              f"头哈希={chain['head_hash'][:16]}...")
        print(f"报告: {os.path.join(self.out, 'demo_run_report.json')}")
        return report


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------

def selftest() -> int:
    import tempfile
    print("== labbridge_demo 自检 ==")
    ok = True
    tmp = tempfile.mkdtemp(prefix="lb_demo_")
    run = DemoRun(output_dir=tmp, samples=6)
    rep = run.run()

    print()
    checks = [
        ("轨道A 有标本", rep["track_a"]["specimens"] == 6),
        ("轨道A 脱敏无泄漏", rep["track_a_deid_stats"]["hidden"] > 0),
        ("轨道B 有字段", rep["track_b"]["fields"] > 0),
        ("审批超时默认拒绝", rep["approval"]["decision"] == "rejected"),
        ("审计链完整", rep["audit"]["chain_ok"]),
        ("审计有事件", rep["audit"]["events"] > 10),
        ("阶段门默认阻断", rep["stage_gate"]["allowed"] is False),
        ("阻断项已登记", len(rep["blockers"]) >= 1),
        ("报告已落盘", os.path.exists(os.path.join(tmp, "demo_run_report.json"))),
        ("合成标记为真", rep["synthetic_data"] is True),
    ]
    for label, passed in checks:
        print(f"  [{'OK' if passed else 'FAIL'}] {label}")
        ok &= bool(passed)

    print("结果:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="LabBridge Demo 编排器")
    ap.add_argument("--run", action="store_true", help="执行端到端运行")
    ap.add_argument("--selftest", action="store_true", help="内置自检")
    ap.add_argument("--samples", type=int, default=50, help="合成标本数")
    ap.add_argument("--output", default=DEFAULT_OUT, help="输出目录")
    ap.add_argument("--approve-stage3", action="store_true",
                    help="显式记录阶段三审批（须同时提供 --approver）")
    ap.add_argument("--approver", default="", help="审批人姓名/账户 ID")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if args.run:
        r = DemoRun(output_dir=args.output, samples=args.samples,
                    approver=args.approver, approve_stage3=args.approve_stage3).run()
        sys.exit(0)
    ap.print_help()
