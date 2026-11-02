#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LabBridge 证据包 / 资产包 / 验收断言 / CAPA（P2）· 纯标准库

Provenance / 反溯说明
---------------------
依据文档 02（量化基线与 acceptance.yaml 建议）、文档 07 第五节（CAPA 六步闭环）、
文档 08 第 4.1 / 4.2 节（资产包清单与证据包目录结构）独立编写。自研，无对应社区资产。

四个产出：
    1. 证据包目录（文档 08 4.2 的九个子目录）+ manifest.json（哈希 + 时间戳）
    2. 离线业务资产包（文档 08 4.1 七类资产）→ 单文件 zip，附 manifest 与哈希
    3. 验收断言执行器 —— 把文档 02 的量化基线变成可执行校验
    4. CAPA 记录（文档 07 第五节 C1–C6），历史条目不得删除

文档 08 的两个演示动作（最能体现「资产解耦」）：
    1. 把工作流配置导出，在另一个平台/本地重新导入并跑通；
    2. 断网展示离线资产包仍能加载知识库与规则。
"""

import hashlib
import json
import os
import zipfile
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from labbridge_auditlog import anchor_file, now_iso
from labbridge_config import Config, config_path

# 文档 08 4.2 证据包目录结构
EVIDENCE_TREE = [
    "00_方针与范围", "01_风险与评估", "02_规则与权限", "03_运行日志",
    "04_变更与版本", "05_CAPA", "06_监视测量", "07_不适用声明", "08_资产包",
]

# 文档 08 4.1 离线业务资产包清单
ASSET_ITEMS = [
    ("标准与行业指南原文", "docs"),
    ("提示词模板", "prompts"),
    ("审核规则（异常标志/危急值/趋势漂移）", "config"),
    ("数据分级与权限映射规则", "config"),
    ("风险清单与 CAPA 记录", "config"),
    ("Agent 工作流配置导出", "workflow"),
    ("内审记录模板、空白表单", "templates"),
]

SCOPE_EXCLUSIONS = """# 07 · 不适用声明（scope_exclusions）

本 Demo 为个人研究性质的受控 POC，以下内容**不在**本项目范围内，
不构成任何合规承诺或临床结论：

1. 不替代原厂 LIS、不替代检验人员签字、不出具临床诊断结论；
2. Demo 本身不等于生产级上线系统（文档 02 红线 4）；
3. 不引入需签署许可的医学术语体系（LOINC / SNOMED CT 等，文档 09 第三节）；
4. ASTM E1381/E1394、CLSI LIS1/LIS2、ISO 9001 / 42001 标准原文为付费标准，
   知识库中只放自撰要点笔记，不存放、不分发标准原文；
5. 量化基线中标注「建议值」的项，正式立项时须按场景重新校准；
6. 政策补贴比例、金额与第三方案例均引自公开推演，立项申报前须以最新官方文件核实。

—— 本声明为证据包固定首页，随证据包一同归档。
"""


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# 1. 验收断言执行器（文档 02）
# ---------------------------------------------------------------------------

_OPS = {
    ">=": lambda a, b: a >= b,
    "==": lambda a, b: a == b,
    "<=": lambda a, b: a <= b,
    ">": lambda a, b: a > b,
    "<": lambda a, b: a < b,
}


class AcceptanceRunner:
    """把 `acceptance.yaml` 的量化基线变成可执行校验。"""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.cfg = config or Config()
        self.baseline: Dict[str, Any] = self.cfg.acceptance.get("baseline", {})

    def run(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        results: List[Dict[str, Any]] = []
        for key, spec in self.baseline.items():
            op = spec.get("op", ">=")
            limit = spec.get("value")
            actual = metrics.get(key)
            if actual is None:
                results.append({"metric": key, "status": "not_measured",
                                "op": op, "threshold": limit, "actual": None,
                                "note": spec.get("note", "")})
                continue
            ok = _OPS.get(op, lambda a, b: False)(actual, limit)
            results.append({"metric": key, "status": "pass" if ok else "fail",
                            "op": op, "threshold": limit, "actual": actual,
                            "note": spec.get("note", "")})
        failed = [r["metric"] for r in results if r["status"] == "fail"]
        unmeasured = [r["metric"] for r in results if r["status"] == "not_measured"]
        return {"all_pass": not failed, "failed": failed, "unmeasured": unmeasured,
                "results": results, "checked_at": now_iso()}

    @staticmethod
    def completeness(results: List[Dict[str, Any]]) -> float:
        """结果完整率：关键字段齐全的记录占比（文档 02 目标 3：≥99%）。"""
        if not results:
            return 0.0
        required = ("patient_pseudo_id", "test_item", "result_value")
        good = sum(1 for r in results
                   if all(r.get(k) not in (None, "", "unknown") for k in required))
        return round(good / len(results), 4)


# ---------------------------------------------------------------------------
# 2. CAPA（文档 07 第五节）
# ---------------------------------------------------------------------------

@dataclass
class CapaRecord:
    issue_id: str
    title: str
    source: str                      # 内审 / 测试缺陷 / 异常事件 / 熔断触发
    c2_cause_type: str = ""          # 体系 / 技术 / 人为
    c2_cause: str = ""
    c3_correction: str = ""          # 纠正：消除已发生的不合格
    c4_corrective_action: str = ""   # 纠正措施：消除根本原因
    c5_verification: str = ""        # 有效性验证
    owner: str = ""
    status: str = "open"             # open / verified / closed
    opened_at: str = field(default_factory=now_iso)
    closed_at: str = ""
    closed_by: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Capa:
    """CAPA 闭环。文档 07 第六节：已关闭风险保留历史条目，**不得删除**。"""

    def __init__(self, path: str = None) -> None:
        self.path = path
        self.records: List[CapaRecord] = []

    def open_issue(self, issue_id: str, title: str, source: str,
                   owner: str = "") -> CapaRecord:
        rec = CapaRecord(issue_id=issue_id, title=title, source=source, owner=owner)
        self.records.append(rec)
        return rec

    def close(self, issue_id: str, closed_by: str, verification: str) -> CapaRecord:
        if not closed_by or closed_by in ("system", "unknown"):
            raise ValueError("关闭人必须是具体的人或账户 ID（文档 05 6.2）")
        rec = next(r for r in self.records if r.issue_id == issue_id)
        rec.status = "closed"
        rec.c5_verification = verification
        rec.closed_by = closed_by
        rec.closed_at = now_iso()
        return rec

    def save(self, path: str = None) -> str:
        p = path or self.path
        if not p:
            raise ValueError("未提供保存路径")
        os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"generated_at": now_iso(),
                       "records": [r.as_dict() for r in self.records]},
                      f, ensure_ascii=False, indent=2)
        return p

    def summary(self) -> Dict[str, Any]:
        return {"total": len(self.records),
                "open": sum(1 for r in self.records if r.status == "open"),
                "closed": sum(1 for r in self.records if r.status == "closed")}


# ---------------------------------------------------------------------------
# 3. 证据包
# ---------------------------------------------------------------------------

class EvidencePack:
    """按文档 08 4.2 生成证据包目录并归集产物。"""

    def __init__(self, root: str, stage: str = "demo", config: Optional[Config] = None,
                 log=None) -> None:
        self.root = root
        self.stage = stage
        self.cfg = config or Config()
        self.log = log
        self.files: List[str] = []

    def build(self) -> Dict[str, Any]:
        for d in EVIDENCE_TREE:
            os.makedirs(os.path.join(self.root, d), exist_ok=True)
        with open(os.path.join(self.root, "07_不适用声明", "scope_exclusions.md"),
                  "w", encoding="utf-8") as f:
            f.write(SCOPE_EXCLUSIONS)

        manifest: Dict[str, Any] = {
            "pack": "LabBridge Demo 证据包",
            "stage": self.stage,
            "generated_at": now_iso(),
            "directories": EVIDENCE_TREE,
            "anchors": [],
        }
        # 文档 05 第七章：受控规则文件锚定时间戳 + 哈希
        for name in ("classification_rules.yaml", "screening_rules.yaml",
                     "critical_values.yaml", "roles.yaml", "access_map.csv",
                     "risk_register.csv", "acceptance.yaml", "stage_gate.yaml"):
            p = config_path(name)
            if os.path.exists(p):
                manifest["anchors"].append(anchor_file(p, signer="（待签署）",
                                                       note=f"受控规则文件 {name}"))
        os.makedirs(self.root, exist_ok=True)
        with open(os.path.join(self.root, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
        if self.log:
            self.log.record("build_evidence_pack", actor_id="system", object=self.root,
                            human_involved=False, result="ok")
        return {"root": os.path.abspath(self.root), "manifest": manifest}

    def put(self, subdir: str, filename: str, content: Any) -> str:
        """把一份产物写进证据包对应目录。"""
        if subdir not in EVIDENCE_TREE:
            raise ValueError(f"未知证据目录: {subdir}（应为 {EVIDENCE_TREE} 之一）")
        path = os.path.join(self.root, subdir, filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if isinstance(content, (dict, list)):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(content, f, ensure_ascii=False, indent=2)
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write(str(content))
        self.files.append(path)
        return path


# ---------------------------------------------------------------------------
# 4. 离线业务资产包（文档 08 4.1）
# ---------------------------------------------------------------------------

def export_asset_pack(output_zip: str, base_dirs: Dict[str, str],
                      version: str = "1.0.0",
                      exclude: Optional[List[str]] = None) -> Dict[str, Any]:
    """把知识库、提示词、规则、映射表、工作流打包成单文件 zip。

    `base_dirs` 形如 {"config": 路径, "docs": 路径, ...}，键对应 ASSET_ITEMS 的第二列。
    产出 manifest.json 内逐文件记录 SHA-256 —— 断网场景下可自证完整性。

    `exclude`：需要排除的路径。**打包目标自身必须排除**——否则当输出 zip 位于
    被打包目录内部时，会出现「边写边读自己」的递归膨胀。
    """
    manifest: Dict[str, Any] = {
        "asset_pack": "LabBridge 离线业务资产包",
        "version": version,
        "exported_at": now_iso(),
        "items": [{"asset": a, "dir": d} for a, d in ASSET_ITEMS],
        "files": [],
        "notice": "本资产包与 AI 平台解耦，可脱离当前模型底座使用（文档 02 目标 4）。",
    }
    os.makedirs(os.path.dirname(os.path.abspath(output_zip)), exist_ok=True)
    out_abs = os.path.realpath(output_zip)
    skip = {out_abs}
    for p in (exclude or []):
        skip.add(os.path.realpath(p))

    def _excluded(path: str) -> bool:
        rp = os.path.realpath(path)
        if rp in skip:
            return True
        # 位于任一排除目录之下
        for s in skip:
            if os.path.isdir(s) and (rp == s or rp.startswith(s + os.sep)):
                return True
        return False

    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as z:
        # 多个资产类目可能指向同一目录（如「审核规则」与「分级权限规则」都在 config/），
        # 按目录去重，避免 zip 内出现重复条目。
        seen_dirs = set()
        for asset, key in ASSET_ITEMS:
            src = base_dirs.get(key)
            if not src or not os.path.exists(src):
                continue
            real = os.path.realpath(src)
            if real in seen_dirs:
                continue
            seen_dirs.add(real)
            if os.path.isfile(src):
                targets = [src]
                root_for_rel = os.path.dirname(src)
            else:
                targets = []
                for dirpath, _, filenames in os.walk(src):
                    for fn in filenames:
                        targets.append(os.path.join(dirpath, fn))
                root_for_rel = src
            for t in targets:
                if _excluded(t):
                    continue
                arc = os.path.join(key, os.path.relpath(t, root_for_rel))
                z.write(t, arc)
                manifest["files"].append({"path": arc, "sha256": sha256_file(t),
                                          "bytes": os.path.getsize(t)})
        manifest["file_count"] = len(manifest["files"])
        manifest["pack_sha256"] = hashlib.sha256(
            json.dumps(manifest["files"], sort_keys=True).encode()).hexdigest()
        z.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
    return {"zip": os.path.abspath(output_zip), "manifest": manifest}


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------

def selftest() -> int:
    import tempfile
    print("== labbridge_evidence 自检 ==")
    ok = True
    tmp = tempfile.mkdtemp(prefix="lb_ev_")

    # 验收断言
    ar = AcceptanceRunner()
    metrics = {"clause_match_accuracy": 0.93, "deidentify_accuracy": 1.0,
               "log_trace_coverage": 1.0, "sample_capture_min": 50,
               "result_completeness": 0.995, "abnormal_agreement": 0.96}
    res = ar.run(metrics)
    print(f"[1] 验收断言: all_pass={res['all_pass']} failed={res['failed']}")
    ok &= res["all_pass"]

    res2 = ar.run({**metrics, "abnormal_agreement": 0.80})
    print(f"[2] 不达标可检出: all_pass={res2['all_pass']} failed={res2['failed']}")
    ok &= (not res2["all_pass"]) and "abnormal_agreement" in res2["failed"]

    res3 = ar.run({"sample_capture_min": 50})
    print(f"[3] 未测项标记: unmeasured={len(res3['unmeasured'])}")
    ok &= len(res3["unmeasured"]) >= 1

    comp = AcceptanceRunner.completeness([
        {"patient_pseudo_id": "A", "test_item": "K", "result_value": 4.0},
        {"patient_pseudo_id": "", "test_item": "K", "result_value": 4.0},
        {"patient_pseudo_id": "B", "test_item": "K", "result_value": None},
    ])
    print(f"[4] 结果完整率: {comp}")
    ok &= abs(comp - round(1 / 3, 4)) < 1e-9

    # 证据包
    ep = EvidencePack(os.path.join(tmp, "evidence_pack"), stage="demo")
    built = ep.build()
    print(f"[5] 证据包目录: {len(built['manifest']['directories'])} 个, "
          f"规则锚定 {len(built['manifest']['anchors'])} 份")
    ok &= len(built["manifest"]["directories"]) == 9
    ok &= os.path.exists(os.path.join(ep.root, "07_不适用声明", "scope_exclusions.md"))

    ep.put("06_监视测量", "metrics.json", metrics)
    ok &= os.path.exists(os.path.join(ep.root, "06_监视测量", "metrics.json"))

    try:
        ep.put("99_不存在", "x.json", {})
        print("[6] 非法目录: FAIL（未拦截）"); ok = False
    except ValueError:
        print("[6] 非法证据目录被拦截: OK"); ok &= True

    # CAPA
    capa = Capa()
    capa.open_issue("CAPA-001", "OCR 手写体置信度低于阈值", "测试缺陷", owner="王工")
    try:
        capa.close("CAPA-001", "system", "已复测")
        print("[7] 无主体关闭 CAPA: FAIL（未拦截）"); ok = False
    except ValueError:
        print("[7] 无主体关闭 CAPA 被拦截: OK"); ok &= True
    capa.close("CAPA-001", "李主任", "复测 100 份，置信度回升至 0.92")
    print(f"[8] CAPA 闭环: {capa.summary()}")
    ok &= capa.summary()["closed"] == 1

    # 资产包
    zpath = os.path.join(tmp, "asset_pack.zip")
    out = export_asset_pack(zpath, {"config": os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config"))})
    print(f"[9] 资产包: {out['manifest']['file_count']} 文件, "
          f"pack_sha256={out['manifest']['pack_sha256'][:16]}...")
    ok &= out["manifest"]["file_count"] > 0 and os.path.exists(zpath)

    print("结果:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
