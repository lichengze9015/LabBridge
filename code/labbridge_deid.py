#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LabBridge 脱敏与访问控制引擎（P0）—— 纯标准库

Provenance / 反溯说明
---------------------
依据文档 02（数据分类）、文档 05（分级/权限/最小暴露面）独立编写。
文档 09 建议用 Presidio（MIT）做 PII 识别；本项目保留该路径（见 `PresidioAdapter`），
但**默认不自依赖**：基层场景要脱的字段是**已知的结构化字段**
（姓名/出生日期/地址/电话/身份证），用「人签署的字段规则 + 正则回扫」即可覆盖，
且每条判定都能回答「依据哪条规则」——这正是外审要追问的。
Presidio 的 NER 价值主要在**自由文本**，本 Demo 的自由文本只有仪器注释，
因此把它降级为可选增强，而不是必经路径。本章未参考 Presidio 源码。

文档 05 第一章的三层模型（本模块的文件级映射）：
    规则层  ← config/classification_rules.yaml（人签署 + 时间戳锚定）
    执行层  ← Classifier / Deidentifier（机器自动打标与脱敏）
    例外层  ← ExceptionQueue（置信度低或规则未覆盖 → 人工裁定）

文档 05 第二章 2.2：分级粒度是**字段级 + 行级**，不是表级。
    字段形态（原文/掩码/隐藏）由「请求者属性 ∩ 字段等级」决定；
    行可见范围由 access_map.csv 中该用户的属性行决定。
"""

import hashlib
import hmac
import os
import re
from dataclasses import dataclass, field as dc_field
from typing import Any, Dict, List, Optional, Tuple

from labbridge_config import Config, config_path

# 脱敏正确率 100% 是文档 02 的硬基线；脱敏后必须回扫，命中即阻断。
LEAK_SCAN_REQUIRED = True


# ---------------------------------------------------------------------------
# 掩码策略（规则层定义 strategy，执行层只负责执行）
# ---------------------------------------------------------------------------

def _mask_keep_ends(v: str) -> str:
    s = str(v)
    if len(s) <= 2:
        return "*" * len(s)
    return s[0] + "*" * (len(s) - 2) + s[-1]


def _redact(_: str) -> str:
    return "[REDACTED]"


def _mask_dob(v: str) -> str:
    """出生日期泛化到年：19900101 → 1990"""
    s = str(v)
    m = re.match(r"(\d{4})", s)
    return m.group(1) + "-**-**" if m else "[REDACTED]"


# 地址保留层级：只保留到「省 + 市（含县级市）+ 区/县」，镇/乡/村/社区/门牌一律不保留。
#
# 不用"一条正则 + 贪婪匹配"的原因：真实数据里存在县级市（如"河北省保定市高碑店市…"），
# 正则回溯会把后面的"街道/社区"当成区县吞进来，导致镇街、村级残留（实测约 2%）。
# 改为逐层最短切分：每层取"第一个层级后缀"，且禁止跨层级吞并（如区县级片段里出现
# 镇/乡/街道/村/社区则判为无效，该层不保留），宁可少保留、不可多保留。
# 更细粒度的关键字：任何层级的片段里出现它们，说明切分越界
_BLOCK_FINE = ("镇", "乡", "街道", "村", "社区", "居委会", "村委会", "组", "队", "号", "路", "街")
_ADDR_LEVELS = (
    # (层名, 后缀, 该层片段内禁止出现的关键字)
    ("省", ("自治区", "特别行政区", "省"), _BLOCK_FINE + ("市", "区", "县", "旗")),
    ("市", ("自治州", "地区", "市", "盟"), _BLOCK_FINE + ("区", "县", "旗")),   # 地级
    ("市", ("市",), _BLOCK_FINE + ("区", "县", "旗")),                          # 县级市
    ("区县", ("区", "县", "旗"), _BLOCK_FINE),
)
_ADDR_BODY_MAX = 7  # 专名最长约 6～7 字（如"科尔沁右翼中"）


def _addr_head(s: str) -> str:
    """按层级切出可保留的地址头（省+市+区县），越界即停。

    补充约束：地级的"地区"只有在已切出省级时才承认——北京的"琉璃河地区""将台地区"
    是乡级单位，若无此约束会被当成地级保留下来（实测 8/8000）。
    """
    pos, kept, has_prov = 0, "", False
    for idx, (_level, suffixes, block) in enumerate(_ADDR_LEVELS):
        hit_i, hit_kw = -1, ""
        for kw in suffixes:
            i = s.find(kw, pos)
            if i >= 0 and (hit_i < 0 or i < hit_i or (i == hit_i and len(kw) > len(hit_kw))):
                hit_i, hit_kw = i, kw
        if hit_i < 0:
            continue
        if hit_kw == "地区" and not has_prov:
            continue
        body = s[pos:hit_i]
        if len(body) > _ADDR_BODY_MAX or any(b in body for b in block):
            continue
        pos = hit_i + len(hit_kw)
        kept += body + hit_kw
        if idx == 0:
            has_prov = True
    return kept


def _mask_address(v: str) -> str:
    """地址保留到区县，门牌与具体住址隐去（镇/乡/村/社区同样不保留）。"""
    s = str(v)
    head = _addr_head(s)
    return (head + "***") if head else "***"


def _mask_phone(v: str) -> str:
    s = re.sub(r"\D", "", str(v))
    if len(s) >= 7:
        return s[:3] + "****" + s[-4:]
    return "***"


def _mask_idcard(v: str) -> str:
    s = str(v)
    if len(s) >= 6:
        return s[:4] + "*" * (len(s) - 6) + s[-2:]
    return "***"


STRATEGIES = {
    "redact": _redact,
    "mask": _mask_keep_ends,
    "generalize_year": _mask_dob,
    "generalize_region": _mask_address,
    "mask_phone": _mask_phone,
    "mask_idcard": _mask_idcard,
}


def pseudonymize(value: str, salt: str) -> str:
    """稳定假名化：同一 salt 下同一原值恒定映射到同一伪 ID，可跨批次关联但不可逆。"""
    digest = hmac.new(salt.encode("utf-8"), str(value).encode("utf-8"), hashlib.sha256)
    return "PSN-" + digest.hexdigest()[:12]


# ---------------------------------------------------------------------------
# 例外队列（文档 05 第一章：例外层）
# ---------------------------------------------------------------------------

@dataclass
class ExceptionItem:
    field: str
    reason: str
    sample_class: str
    record_index: int
    decided_by: str = ""
    decision: str = ""       # pending / approved / rejected
    decided_at: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"field": self.field, "reason": self.reason,
                "sample_class": self.sample_class, "record_index": self.record_index,
                "decided_by": self.decided_by, "decision": self.decision,
                "decided_at": self.decided_at}


class ExceptionQueue:
    """机器不确定的条目进这里，由人裁定。核心目的：人的工作量不随数据量线性增长。"""

    def __init__(self) -> None:
        self.items: List[ExceptionItem] = []

    def push(self, field: str, reason: str, sample_class: str, record_index: int) -> None:
        self.items.append(ExceptionItem(field, reason, sample_class, record_index))

    def pending(self) -> List[ExceptionItem]:
        return [i for i in self.items if i.decision == ""]

    def decide(self, index: int, decision: str, decided_by: str, at: str) -> None:
        from labbridge_auditlog import now_iso
        item = self.items[index]
        item.decision = decision
        item.decided_by = decided_by
        item.decided_at = at or now_iso()

    def as_dicts(self) -> List[Dict[str, Any]]:
        return [i.as_dict() for i in self.items]


# ---------------------------------------------------------------------------
# 引擎
# ---------------------------------------------------------------------------

class Deidentifier:
    """字段级 + 行级授权脱敏引擎。"""

    def __init__(self, config: Optional[Config] = None, salt: str = None, log=None):
        self.cfg = config or Config()
        self.salt = salt or os.environ.get("LABBRIDGE_PSN_SALT", "labbridge-demo-salt")
        self.log = log
        self.exceptions = ExceptionQueue()
        self.leaks: List[Dict[str, Any]] = []
        self.field_class = self.cfg.field_class
        self.form_matrix = self.cfg.form_matrix
        self.strategies: Dict[str, str] = self.cfg.classification.get(
            "mask_strategy", {})
        self.leak_patterns = [(p["pattern"], p["tag"])
                              for p in self.cfg.classification.get("leak_patterns", [])]
        self.access_map = {row["user_id"]: row for row in self.cfg.access_map}

    # -- 授权（文档 05 第八章伪代码的落地版） --------------------------------

    def form_for(self, role: str, level: str) -> str:
        return self.form_matrix.get(role, {}).get(level, "hidden")

    def row_visible(self, user_id: str, row: Dict[str, Any]) -> bool:
        """行级过滤：由 access_map 中该用户的属性行决定。"""
        attrs = self.access_map.get(user_id)
        if not attrs:
            return False
        scope = (attrs.get("scope") or "").strip()
        if scope in ("", "*", "all"):
            return True
        dept = str(row.get("dept") or row.get("department") or "")
        region = str(row.get("region") or "")
        return scope in (dept, region) or scope == dept

    def authorize(self, user_id: str, role: str, field: str,
                  row: Dict[str, Any]) -> Tuple[str, str]:
        """返回 (形态, 命中策略ID)。形态 ∈ raw / mask / hidden。"""
        if not self.row_visible(user_id, row):
            return "hidden", "row-filter-deny"
        level = self.field_class.get(field, self.cfg.classification.get(
            "default_class", "internal"))
        form = self.form_for(role, level)
        return form, f"{level}-{form}"

    # -- 脱敏 ---------------------------------------------------------------

    def _apply(self, field: str, value: Any) -> Any:
        strategy = self.strategies.get(field, "mask")
        fn = STRATEGIES.get(strategy, _mask_keep_ends)
        return fn(value)

    def deidentify(self, records: List[Dict[str, Any]], actor_id: str = "system",
                   role: str = "technician", request_raw: bool = False,
                   data_source: str = "") -> Dict[str, Any]:
        """按字段分级脱敏。默认掩码；取原文必须 request_raw 并自动记例外。

        返回中 `deidentify_ok` 只有在「回扫无命中」时才为 True——
        这是文档 02「脱敏正确率 100%」的可执行定义。
        """
        out: List[Dict[str, Any]] = []
        self.leaks = []
        stats = {"raw": 0, "mask": 0, "hidden": 0}

        for idx, rec in enumerate(records):
            new: Dict[str, Any] = {}
            for k, v in rec.items():
                level = self.field_class.get(k, self.cfg.classification.get(
                    "default_class", "internal"))
                if level == "unknown":
                    # 规则未覆盖 → 例外层，不由机器拍板
                    self.exceptions.push(k, "规则未覆盖该字段", level, idx)
                    new[k] = self._apply(k, v)
                    stats["mask"] += 1
                    continue
                form, policy = self.authorize(actor_id, role, k, rec)
                if form == "hidden":
                    stats["hidden"] += 1
                    continue
                if level == "sensitive" and form == "mask" and not request_raw:
                    new[k] = self._apply(k, v)
                    stats["mask"] += 1
                else:
                    new[k] = v
                    stats["raw"] += 1
                    if level == "sensitive":
                        self.exceptions.push(k, "request_raw 取原文", level, idx)
            if "patient_pseudo_id" in new and new.get("patient_pseudo_id"):
                new["patient_pseudo_id"] = pseudonymize(new["patient_pseudo_id"], self.salt)
            out.append(new)

        if LEAK_SCAN_REQUIRED:
            out = self._leak_scan(out)

        if self.log:
            self.log.record("deidentify", actor_id=actor_id, actor_role=role,
                            object=f"{len(records)} records", data_class="sensitive",
                            field_form="mask", policy_hit="classification_rules.yaml",
                            data_source=data_source, human_involved=request_raw,
                            result="leak_blocked" if self.leaks else "ok",
                            extra={"stats": stats, "leaks": len(self.leaks)})
        return {
            "records": out,
            "stats": stats,
            "leak_hits": self.leaks,
            "deidentify_ok": not self.leaks,
            "exceptions": self.exceptions.as_dicts(),
            "pending_exceptions": len(self.exceptions.pending()),
        }

    def _leak_scan(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """脱敏后正则回扫（文档 02：脱敏正确率 100% → 命中即告警并阻断输出）。

        本引擎自产的假名（PSN-<12位十六进制>）跳过回扫：它是 HMAC 摘要，
        字符集固定为 0-9a-f，纯数字串（如 PSN-0215551234xx）会被电话/座机
        正则误伤——真实 NHANES 数据回放（8727 人）实测 441 条误改写，
        属确定性误报，不是漏报（见 output/07 号报告）。
        """
        for idx, rec in enumerate(records):
            for k, v in list(rec.items()):
                s = str(v)
                if k == "patient_pseudo_id" and re.fullmatch(
                        r"PSN-[0-9a-f]{12}", s):
                    continue
                for pat, tag in self.leak_patterns:
                    if re.search(pat, s):
                        self.leaks.append({"field": k, "pattern": tag,
                                           "record_index": idx})
                        rec[k] = "[REDACTED]"
        return records


# ---------------------------------------------------------------------------
# 可选适配器：Presidio（MIT）
# ---------------------------------------------------------------------------

class PresidioAdapter:
    """自由文本 PII 识别的可选增强路径。

    文档 09 定位：Presidio（MIT，11.4k★）是事实标准，适合自由文本的 NER 识别。
    本 Demo 的字段是已知结构化字段，规则已覆盖；若后续要做「仪器注释/自由文本
    报告」的 PII 识别，再启用它。启用时同样必须套上本项目的规则文件与审计日志，
    不能把「上游默认行为」当作「人定规则」交出去。
    """

    PACKAGE = "presidio_analyzer"
    LICENSE = "MIT"
    UPSTREAM_NOTE = "仓库已从 microsoft/presidio 迁至 data-privacy-stack/presidio"

    @classmethod
    def available(cls) -> bool:
        import importlib.util
        return importlib.util.find_spec(cls.PACKAGE) is not None

    @classmethod
    def status(cls) -> Dict[str, Any]:
        return {"package": cls.PACKAGE, "available": cls.available(),
                "license": cls.LICENSE, "note": cls.UPSTREAM_NOTE,
                "required": False,
                "fallback": "Deidentifier（字段规则 + 正则回扫，覆盖结构化字段）"}


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------

def selftest() -> int:
    print("== labbridge_deid 自检 ==")
    ok = True
    d = Deidentifier()

    recs = [{
        "patient_id": "P00001", "patient_name": "张三丰", "dob": "19900101",
        "address": "福建省沙县区府前路1号", "phone": "13800138000",
        "id_card": "350101199001011234",
        "test_item": "K", "result_value": 7.3, "abnormal_flag": "H",
        "dept": "检验科",
    }]

    # 1 普通检验员：敏感字段应隐藏
    r1 = d.deidentify(recs, actor_id="tech01", role="technician")
    got1 = r1["records"][0]
    print(f"[1] 检验员视图字段: {sorted(got1.keys())}")
    ok &= "patient_name" not in got1 and "phone" not in got1
    ok &= got1["test_item"] == "K" and got1["result_value"] == 7.3

    # 2 主任：敏感字段掩码
    d2 = Deidentifier()
    r2 = d2.deidentify(recs, actor_id="dir01", role="director")
    got2 = r2["records"][0]
    print(f"[2] 主任视图: name={got2.get('patient_name')} phone={got2.get('phone')} "
          f"dob={got2.get('dob')} addr={got2.get('address')}")
    ok &= got2.get("patient_name") != "张三丰" and "****" in str(got2.get("phone"))

    # 3 脱敏后回扫：构造一条绕过规则的泄漏
    d3 = Deidentifier()
    r3 = d3.deidentify([{"patient_id": "P2", "instrument_note": "联系13800138000",
                         "result_value": 1.0}], actor_id="dir01", role="director")
    print(f"[3] 回扫命中: {r3['leak_hits']} deidentify_ok={r3['deidentify_ok']}")
    ok &= (not r3["deidentify_ok"]) and len(r3["leak_hits"]) >= 1

    # 4 取原文必须记例外
    d4 = Deidentifier()
    r4 = d4.deidentify(recs, actor_id="dir01", role="director", request_raw=True)
    print(f"[4] request_raw 例外数: {len(r4['exceptions'])}")
    ok &= len(r4["exceptions"]) > 0

    # 5 假名化稳定且不可逆
    a1 = pseudonymize("P00001", "s")
    a2 = pseudonymize("P00001", "s")
    b1 = pseudonymize("P00002", "s")
    print(f"[5] 假名化: 稳定={a1 == a2} 区分={a1 != b1} 样例={a1}")
    ok &= a1 == a2 and a1 != b1

    # 6 行级过滤
    d5 = Deidentifier()
    vis_all = d5.row_visible("tech01", {"dept": "检验科"})
    vis_none = d5.row_visible("tech02", {"dept": "检验科"})
    print(f"[6] 行级过滤: tech01(检验科)={vis_all} tech02(其他科)={vis_none}")
    ok &= vis_all and not vis_none

    # 7 规则未覆盖进例外层
    d6 = Deidentifier()
    r7 = d6.deidentify([{"mystery_field": "x", "result_value": 1.0}],
                       actor_id="dir01", role="director")
    print(f"[7] 未覆盖字段例外: {r7['pending_exceptions']}")
    ok &= r7["pending_exceptions"] >= 1

    # 8 社区包状态
    st = PresidioAdapter.status()
    print(f"[8] Presidio 适配器: available={st['available']} required={st['required']}")
    ok &= st["required"] is False

    # 9 回归（真实 NHANES 数据回放发现）：自产假名不得被回扫改写
    d9 = Deidentifier()
    pid = pseudonymize("NH-84005", "s")
    d9.deidentify([{"patient_pseudo_id": pid, "result_value": 7.3,
                    "dept": "检验科", "region": "本院"}],
                  actor_id="tech01", role="technician")
    same = d9.deidentify([{"patient_pseudo_id": pid, "result_value": 7.3,
                           "dept": "检验科", "region": "本院"}],
                         actor_id="tech01", role="technician")
    kept = bool(re.fullmatch(r"PSN-[0-9a-f]{12}",
                             same["records"][0]["patient_pseudo_id"] or ""))
    # 而真实手机号仍必须被拦
    d9b = Deidentifier()
    hit = d9b.deidentify([{"patient_pseudo_id": pid, "instrument_note":
                           "联系电话 13812345678", "dept": "检验科",
                           "region": "本院"}],
                         actor_id="tech01", role="technician")
    blocked = "[REDACTED]" in str(hit["records"][0].get("instrument_note", ""))
    print(f"[9] 回扫回归: 假名保留={kept} 真手机号拦截={blocked}")
    ok &= kept and blocked

    print("结果:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
