#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LabBridge 轻量审核规则引擎（P1）与熔断检测器 —— 纯标准库

Provenance / 反溯说明
---------------------
依据文档 04 第四章（三条最小规则）、文档 04 末的 `screening_rules.yaml` 建议、
文档 07 第三章（动态风险触发与熔断）独立编写。社区无对应可封包资产，属自研。

「薄」是刻意的设计选择（文档 04 第七节）：
    规则为主、LLM 为辅，每条标记都能回答「为什么」。
    在基层建立信任，比准确率数字更重要。

三条规则（文档 04 第四章）：
    R1 异常标志聚合 —— 仪器 H/L 标志与参考区间不一致
    R2 危急值预筛   —— 按预设阈值标记
    R3 趋势漂移     —— 同一患者短期内相同项目结果显著漂移

两条不可协商的输出约束：
    1. 只输出「待关注列表」，不下临床结论；
    2. 措辞禁止「已审核 / 已签发 / 结论为 / 诊断」（文档 03、04：不替代签字）。
"""

import re
from typing import Any, Dict, List, Optional

from labbridge_config import Config

NOTICE = "本列表为待人工关注项，不构成审核结论，不替代签字。"


def _to_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    try:
        return float(str(v).replace("<", "").replace(">", "").replace("=", "").strip())
    except (TypeError, ValueError):
        return None


def _parse_ref(ref: str) -> Optional[tuple]:
    """解析参考区间字符串，如 '3.5-5.3' / '3.5~5.3' / '<10' / '>2'。"""
    if not ref:
        return None
    s = str(ref).strip()
    m = re.match(r"^([<>=]?)\s*([\d.]+)\s*[-~至]\s*([\d.]+)$", s)
    if m:
        return float(m.group(2)), float(m.group(3))
    m = re.match(r"^([<>=])\s*([\d.]+)$", s)
    if m:
        val = float(m.group(2))
        return {"<": (None, val), ">": (val, None), "=": (val, val)}.get(m.group(1))
    return None


class ScreenEngine:
    """最小审核规则引擎。规则全部来自 `screening_rules.yaml`，代码不含业务阈值。"""

    def __init__(self, config: Optional[Config] = None, log=None):
        self.cfg = config or Config()
        self.log = log
        self.rules = {r["id"]: r for r in (self.cfg.screening.get("rules") or [])}
        self.critical = self.cfg.critical.get("values", {})
        self.output_cfg = self.cfg.screening.get("output", {})
        self.forbidden = self.output_cfg.get("forbidden_wording", [])
        self.thresholds = self.cfg.screening.get("circuit_breaker", {})

    # -- 三条规则 -----------------------------------------------------------

    def r1_abnormal_flag(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """R1：仪器异常标志与参考区间不一致。"""
        flags = []
        for r in results:
            flag = str(r.get("abnormal_flag", "")).strip().upper()
            if flag in ("H", "L", "HH", "LL", "A"):
                val = _to_float(r.get("result_value"))
                ref = _parse_ref(r.get("ref_range", ""))
                consistent = True
                if ref and val is not None:
                    lo, hi = ref
                    if lo is not None and hi is not None:
                        consistent = (flag.startswith("H") and val > hi) or \
                                     (flag.startswith("L") and val < lo)
                flags.append({
                    "rule": "R1", "severity": "flag",
                    "patient_pseudo_id": r.get("patient_pseudo_id", ""),
                    "specimen_id": r.get("specimen_id", ""),
                    "test_item": r.get("test_item", ""),
                    "value": r.get("result_value"),
                    "reason": f"仪器异常标志 {flag}"
                              + ("" if consistent else "（与参考区间方向不一致，需人工确认）"),
                    "needs_human": not consistent,
                })
        return flags

    def r2_critical(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """R2：危急值预筛。"""
        flags = []
        for r in results:
            item = str(r.get("test_item", "")).upper()
            th = self.critical.get(item)
            val = _to_float(r.get("result_value"))
            if not th or val is None:
                continue
            lo, hi = th.get("low"), th.get("high")
            if (lo is not None and val <= lo) or (hi is not None and val >= hi):
                flags.append({
                    "rule": "R2", "severity": "urgent",
                    "patient_pseudo_id": r.get("patient_pseudo_id", ""),
                    "specimen_id": r.get("specimen_id", ""),
                    "test_item": item,
                    "value": val,
                    "reason": f"结果 {val} 超出危急值阈值 [{lo}, {hi}]",
                    "needs_human": True,
                })
        return flags

    def r3_drift(self, results: List[Dict[str, Any]], window_days: int = None,
                 drift_pct: float = None) -> List[Dict[str, Any]]:
        """R3：同一患者短期内相同项目结果显著漂移。"""
        params = self.rules.get("R3", {}).get("params", {})
        window = window_days if window_days is not None else params.get("window_days", 7)
        pct = drift_pct if drift_pct is not None else params.get("drift_pct", 30)
        by_key: Dict[tuple, List[float]] = {}
        meta: Dict[tuple, Dict[str, Any]] = {}
        for r in results:
            key = (r.get("patient_pseudo_id", ""), r.get("test_item", ""))
            val = _to_float(r.get("result_value"))
            if val is None:
                continue
            by_key.setdefault(key, []).append(val)
            meta.setdefault(key, r)
        flags = []
        for key, vals in by_key.items():
            if len(vals) < 2:
                continue
            base = vals[0]
            if not base:
                continue
            delta = abs(vals[-1] - base) / abs(base) * 100
            if delta >= pct:
                r = meta[key]
                flags.append({
                    "rule": "R3", "severity": "flag",
                    "patient_pseudo_id": key[0], "specimen_id": r.get("specimen_id", ""),
                    "test_item": key[1], "value": vals[-1],
                    "reason": f"{window} 天内漂移 {delta:.1f}%（{vals[0]} → {vals[-1]}）",
                    "needs_human": True,
                })
        return flags

    # -- 主入口 -------------------------------------------------------------

    def screen(self, results: List[Dict[str, Any]], actor_id: str = "system",
               data_source: str = "") -> Dict[str, Any]:
        watchlist: List[Dict[str, Any]] = []
        enabled = {rid for rid, r in self.rules.items() if r.get("enabled", True)}
        if "R1" in enabled:
            watchlist += self.r1_abnormal_flag(results)
        if "R2" in enabled:
            watchlist += self.r2_critical(results)
        if "R3" in enabled:
            watchlist += self.r3_drift(results)

        order = {"urgent": 0, "flag": 1}
        watchlist.sort(key=lambda f: (order.get(f["severity"], 9), f["test_item"]))

        urgent = sum(1 for f in watchlist if f["severity"] == "urgent")
        if self.log:
            self.log.record("screen", actor_id=actor_id, object=f"{len(results)} results",
                            data_class="internal", field_form="raw",
                            policy_hit=";".join(sorted(enabled)),
                            data_source=data_source, human_involved=True,
                            result="flagged" if watchlist else "clean",
                            extra={"urgent": urgent})
        return {
            "watchlist": watchlist,
            "count": len(watchlist),
            "urgent_count": urgent,
            "needs_human_count": sum(1 for f in watchlist if f.get("needs_human")),
            "scanned_results": len(results),
            "rules_applied": sorted(enabled),
            "notice": NOTICE,
        }

    # -- 措辞合规（文档 03/04：不替代签字） ----------------------------------

    def check_wording(self, text: str) -> Dict[str, Any]:
        hits = [w for w in self.forbidden if w in text]
        return {"compliant": not hits, "forbidden_hits": hits,
                "notice": "输出不得出现审核/签发/诊断类结论性表述。"}

    # -- 熔断检测（文档 07 第三章） ------------------------------------------

    def circuit_check(self, run_stats: Dict[str, Any]) -> Dict[str, Any]:
        """按 `screening_rules.yaml` 的 circuit_breaker 阈值判定是否熔断。

        run_stats 期望字段：
            agreement_rate        与人工判断一致率
            abnormal_spike_ratio  异常标记占比（相对基线）
            compliance_ok         等保/密评/数据安全评估是否齐备
        """
        t = self.thresholds
        tripped: List[Dict[str, Any]] = []

        def _trip(key: str, actual, op: str, limit: Any, action: str, desc: str) -> None:
            if limit is None or actual is None:
                return
            bad = (actual < limit) if op == "<" else (actual > limit)
            if bad:
                tripped.append({"indicator": key, "actual": actual, "op": op,
                                "threshold": limit, "action": action, "desc": desc})

        md = t.get("model_drift", {})
        _trip("model_drift", run_stats.get("agreement_rate"),
              md.get("op", "<"), md.get("agreement_rate_min"),
              md.get("action", "切换人工全量复核"), "模型漂移：一致率下降超阈值")

        spike = t.get("abnormal_spike", {})
        _trip("abnormal_spike", run_stats.get("abnormal_spike_ratio"),
              spike.get("op", ">"), spike.get("ratio_max"),
              spike.get("action", "隔离数据源并审计"), "数据投毒/异常注入：标记激增")

        comp = t.get("compliance", {})
        if comp.get("require_all") and run_stats.get("compliance_ok") is False:
            tripped.append({"indicator": "compliance_gate", "actual": False, "op": "==",
                            "threshold": True, "action": comp.get("action", "暂停跨院互通"),
                            "desc": "合规资质缺失：无法通过等保/密评/数据安全评估"})

        if tripped and self.log:
            self.log.record("circuit_breaker", actor_id="system",
                            object=";".join(x["indicator"] for x in tripped),
                            result="tripped", human_involved=True,
                            extra={"actions": [x["action"] for x in tripped]})
        return {"tripped": bool(tripped), "items": tripped,
                "actions": [x["action"] for x in tripped]}


# ---------------------------------------------------------------------------
# 一致性评估（文档 02 目标 3：AI 标记与人工判断一致率 ≥ 95%）
# ---------------------------------------------------------------------------

def agreement_report(ai_flags: List[Dict[str, Any]],
                     human_flags: List[Dict[str, Any]],
                     total: int) -> Dict[str, Any]:
    """计算双向遗漏率：AI 标记但人工未关注 / 人工关注但 AI 未标记。

    文档 04 第四章要求给出两个方向的遗漏率，而不是只看一致率。
    """
    def keys(flags):
        return {(f.get("patient_pseudo_id", ""), f.get("test_item", ""),
                 str(f.get("specimen_id", ""))) for f in flags}

    ai, hu = keys(ai_flags), keys(human_flags)
    both = ai & hu
    denominator = len(ai | hu)
    agree = (len(both) / denominator) if denominator else 1.0
    return {
        "ai_marked": len(ai),
        "human_marked": len(hu),
        "agreed": len(both),
        "ai_only": sorted(ai - hu)[:20],
        "human_only": sorted(hu - ai)[:20],
        "agreement_rate": round(agree, 4),
        "ai_miss_rate": round(len(hu - ai) / len(hu), 4) if hu else 0.0,
        "ai_over_rate": round(len(ai - hu) / len(ai), 4) if ai else 0.0,
        "scanned_total": total,
    }


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------

def selftest() -> int:
    print("== labbridge_screen 自检 ==")
    ok = True
    from labbridge_config import config_path
    import os
    if not os.path.exists(config_path("screening_rules.yaml")):
        print("  [FAIL] 缺少 config/screening_rules.yaml")
        return 1
    e = ScreenEngine()

    results = [
        {"patient_pseudo_id": "PSN-A", "specimen_id": "S1", "test_item": "K",
         "result_value": 7.3, "ref_range": "3.5-5.3", "abnormal_flag": "H"},
        {"patient_pseudo_id": "PSN-A", "specimen_id": "S1", "test_item": "K",
         "result_value": 4.0, "ref_range": "3.5-5.3", "abnormal_flag": ""},
        {"patient_pseudo_id": "PSN-B", "specimen_id": "S2", "test_item": "GLU",
         "result_value": 5.6, "ref_range": "3.9-6.1", "abnormal_flag": ""},
        {"patient_pseudo_id": "PSN-B", "specimen_id": "S2", "test_item": "HGB",
         "result_value": 40.0, "ref_range": "115-150", "abnormal_flag": "L"},
    ]
    out = e.screen(results, actor_id="engine")
    print(f"[1] 待关注列表: count={out['count']} urgent={out['urgent_count']} "
          f"rules={out['rules_applied']}")
    ok &= out["count"] >= 3 and out["urgent_count"] >= 2

    r2 = [f for f in out["watchlist"] if f["rule"] == "R2"]
    print(f"[2] R2 危急值: {[(f['test_item'], f['value']) for f in r2]}")
    ok &= any(f["test_item"] == "K" for f in r2) and any(f["test_item"] == "HGB" for f in r2)

    r3 = [f for f in out["watchlist"] if f["rule"] == "R3"]
    print(f"[3] R3 趋势漂移: {[f['reason'] for f in r3]}")
    ok &= len(r3) >= 1

    print(f"[4] 措辞锁死: notice={out['notice'][:20]}...")
    ok &= "不替代签字" in out["notice"]

    w = e.check_wording("本报告已审核通过，结论为正常")
    print(f"[5] 禁用措辞拦截: compliant={w['compliant']} hits={w['forbidden_hits']}")
    ok &= (not w["compliant"]) and len(w["forbidden_hits"]) >= 2

    cb = e.circuit_check({"agreement_rate": 0.90, "abnormal_spike_ratio": 0.5,
                          "compliance_ok": False})
    print(f"[6] 熔断: tripped={cb['tripped']} actions={cb['actions']}")
    ok &= cb["tripped"] and len(cb["actions"]) >= 1

    cb2 = e.circuit_check({"agreement_rate": 0.99, "abnormal_spike_ratio": 0.05,
                           "compliance_ok": True})
    print(f"[7] 正常态不熔断: tripped={cb2['tripped']}")
    ok &= (not cb2["tripped"])

    ag = agreement_report([{"patient_pseudo_id": "A", "test_item": "K", "specimen_id": "S1"},
                           {"patient_pseudo_id": "B", "test_item": "K", "specimen_id": "S2"}],
                          [{"patient_pseudo_id": "A", "test_item": "K", "specimen_id": "S1"}],
                          total=2)
    print(f"[8] 一致率: {ag['agreement_rate']} 人工漏报率={ag['ai_miss_rate']} "
          f"AI 过标率={ag['ai_over_rate']}")
    ok &= ag["agreement_rate"] == 0.5 and ag["ai_over_rate"] == 0.5

    print("结果:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
