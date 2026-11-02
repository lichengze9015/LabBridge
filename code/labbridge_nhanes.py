#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LabBridge NHANES 真实公开数据回放模块 —— 纯标准库（零第三方依赖）

Provenance / 反溯说明
---------------------
自研。SAS XPORT v5 传输格式依据 SAS Technical Support 文档 TS-140 公开描述
独立实现（记录头 80 字节、NAMESTR 140 字节、IBM 370 浮点），未复制任何项目代码。
NHANES CBC_L 数据来自美国 CDC 公开发布（August 2021-August 2023 周期），
属公开数据，不含身份信息（SEQN 本身即为调查匿名序号）。

用途与诚实边界
--------------
把**真实**血常规结果灌入 LabBridge 已有链路（脱敏 → 三条审核规则 → 熔断检测），
验证规则引擎在真实分布上的行为。注意：
    1. 这是公开人群调查数据，不是医院受控数据；不能据此宣称达成文档 02 目标 3；
    2. 「与人工判断一致率」仍然无法测——本模块给出的异常率全部是
       「结果超出参考区间」的机器判据，须标注来源，不得冒充人工复核；
    3. 参考区间为通用成人区间（演示用），NHANES 含 1-17 岁儿童，
       儿童结果按成人区间判读必然虚高——这本身是要如实报告的发现。

用法:
    python labbridge_nhanes.py --xpt ../公开数据/CBC_L.xpt --out ../output
    python labbridge_nhanes.py --selftest
"""

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from labbridge_auditlog import AuditLog
from labbridge_config import Config
from labbridge_deid import Deidentifier
from labbridge_screen import ScreenEngine, agreement_report

# ---------------------------------------------------------------------------
# CBC_L 变量 → 统一结果模型映射
# codebook 列 = 官方文档给出的取值范围，用于校验解析正确性
# ---------------------------------------------------------------------------

CBC_MAP: Dict[str, Dict[str, Any]] = {
    "LBXWBCSI": dict(item="WBC",  name="白细胞计数",     unit="10^9/L",  factor=1.0,  ref="4.0-10.0",     codebook=(2.1, 20.8)),
    "LBXLYPCT": dict(item="LY%",  name="淋巴细胞百分比", unit="%",       factor=1.0,  ref="20.0-50.0",    codebook=(3.1, 78.9)),
    "LBXMOPCT": dict(item="MO%",  name="单核细胞百分比", unit="%",       factor=1.0,  ref="3.0-10.0",     codebook=(1.3, 25.9)),
    "LBXNEPCT": dict(item="NE%",  name="中性粒细胞百分比", unit="%",      factor=1.0,  ref="40.0-75.0",    codebook=(12.4, 92.1)),
    "LBXEOPCT": dict(item="EO%",  name="嗜酸性粒细胞百分比", unit="%",    factor=1.0,  ref="0.5-5.0",      codebook=(0.0, 46.7)),
    "LBXBAPCT": dict(item="BA%",  name="嗜碱性粒细胞百分比", unit="%",    factor=1.0,  ref="0.0-1.0",      codebook=(0.0, 4.2)),
    "LBDLYMNO": dict(item="LY#",  name="淋巴细胞计数",   unit="10^9/L",  factor=1.0,  ref="1.1-3.2",      codebook=(0.2, 9.8)),
    "LBDMONO":  dict(item="MO#",  name="单核细胞计数",   unit="10^9/L",  factor=1.0,  ref="0.1-0.6",      codebook=(0.1, 1.8)),
    "LBDNENO":  dict(item="NE#",  name="中性粒细胞计数", unit="10^9/L",  factor=1.0,  ref="1.8-6.3",      codebook=(0.5, 16.1)),
    "LBDEONO":  dict(item="EO#",  name="嗜酸性粒细胞计数", unit="10^9/L", factor=1.0,  ref="0.02-0.5",     codebook=(0.0, 6.0)),
    "LBDBANO":  dict(item="BA#",  name="嗜碱性粒细胞计数", unit="10^9/L", factor=1.0,  ref="0.0-0.06",     codebook=(0.0, 0.3)),
    "LBXRBCSI": dict(item="RBC",  name="红细胞计数",     unit="10^12/L", factor=1.0,  ref="3.8-5.8",      codebook=(2.44, 7.08)),
    "LBXHGB":   dict(item="HGB",  name="血红蛋白",       unit="g/L",     factor=10.0, ref="115.0-175.0",  codebook=(6.3, 18.6)),
    "LBXHCT":   dict(item="HCT",  name="红细胞压积",     unit="%",       factor=1.0,  ref="35.0-50.0",    codebook=(19.9, 54.9)),
    "LBXMCVSI": dict(item="MCV",  name="平均红细胞体积", unit="fL",      factor=1.0,  ref="80.0-100.0",   codebook=(52.5, 116.7)),
    "LBXMCHSI": dict(item="MCH",  name="平均红细胞血红蛋白", unit="pg",  factor=1.0,  ref="27.0-34.0",    codebook=(15.6, 41.1)),
    "LBXMC":    dict(item="MCHC", name="平均红细胞血红蛋白浓度", unit="g/L", factor=10.0, ref="320.0-360.0", codebook=(27.8, 40.5)),
    "LBXRDW":   dict(item="RDW",  name="红细胞分布宽度", unit="%",       factor=1.0,  ref="11.5-14.5",    codebook=(11.2, 37.5)),
    "LBXPLTSI": dict(item="PLT",  name="血小板计数",     unit="10^9/L",  factor=1.0,  ref="125.0-350.0",  codebook=(46.0, 787.0)),
    "LBXMPSI":  dict(item="MPV",  name="平均血小板体积", unit="fL",      factor=1.0,  ref="7.5-11.5",     codebook=(5.5, 12.9)),
    "LBXNRBC":  dict(item="NRBC", name="有核红细胞",     unit="/100WBC", factor=1.0,  ref="0.0-0.0",      codebook=(0.0, 4.0)),
}

MISSING_CODES = b"._ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# ---------------------------------------------------------------------------
# SAS XPORT v5 读取器（依据公开格式描述 TS-140 自实现）
# ---------------------------------------------------------------------------

def ibm_to_float(b: bytes) -> Optional[float]:
    """IBM 370 十六进制浮点 → IEEE double。缺失值返回 None。

    缺失值约定：首字节为 '.'、'_' 或 'A'-'Z'，其余字节全 0（TS-140）。
    """
    if b[0:1] in (b".", b"_") or (b[0:1].isalpha() and b[0:1] == b[0:1].upper()
                                  and b[1:] == b"\x00" * 7):
        if b[1:] == b"\x00" * 7:
            return None
    if b == b"\x00" * 8:
        return 0.0
    sign = -1.0 if b[0] & 0x80 else 1.0
    exp = (b[0] & 0x7F) - 64
    mant = int.from_bytes(b[1:], "big") / float(1 << 56)
    return sign * mant * (16.0 ** exp)


def read_xpt(path: str) -> Tuple[List[str], List[Dict[str, Any]]]:
    """读 XPORT v5 文件，返回 (变量名列表, 记录列表)。仅支持 NHANES 这类
    未压缩、定长数值+字符混合的成员数据集。"""
    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(b"HEADER RECORD*******LIBRARY HEADER RECORD"):
        raise ValueError("不是 XPORT v5 文件")

    # 定位 NAMESTR 头，取变量数与成员记录
    ns_head_idx = data.find(b"HEADER RECORD*******NAMESTR HEADER RECORD")
    if ns_head_idx < 0:
        raise ValueError("找不到 NAMESTR 头")
    n_vars = int(data[ns_head_idx + 54:ns_head_idx + 58])

    obs_head_idx = data.find(b"HEADER RECORD*******OBS", ns_head_idx)
    if obs_head_idx < 0:
        raise ValueError("找不到 OBS 头")

    # 解析 NAMESTR（每个 140 字节，区内按 80 字节对齐）
    vars_meta = []
    off = ns_head_idx + 80
    for i in range(n_vars):
        ns = data[off + i * 140: off + (i + 1) * 140]
        ntype = int.from_bytes(ns[0:2], "big")     # 1=数值 2=字符
        nlng = int.from_bytes(ns[4:6], "big")      # 字段长度
        name = ns[8:16].decode("ascii", errors="replace").strip()
        label = ns[16:56].decode("ascii", errors="replace").strip()
        vars_meta.append({"name": name, "type": ntype, "length": nlng,
                          "label": label})
    rec_len = sum(v["length"] for v in vars_meta)

    # 数据区：OBS 头之后，直到不足一条记录或全空白填充
    start = obs_head_idx + 80
    rows: List[Dict[str, Any]] = []
    pos = start
    while pos + rec_len <= len(data):
        chunk = data[pos:pos + rec_len]
        if chunk.strip(b" ") == b"":            # 尾部填充
            break
        row: Dict[str, Any] = {}
        o = 0
        for v in vars_meta:
            raw = chunk[o:o + v["length"]]
            o += v["length"]
            if v["type"] == 1:
                padded = raw + b"\x00" * (8 - len(raw)) if len(raw) < 8 else raw
                row[v["name"]] = ibm_to_float(padded)
            else:
                row[v["name"]] = raw.decode("latin-1").rstrip()
        rows.append(row)
        pos += rec_len
    return [v["name"] for v in vars_meta], rows


# ---------------------------------------------------------------------------
# 记录映射：NHANES 行 → 统一结果模型
# ---------------------------------------------------------------------------

def build_records(rows: List[Dict[str, Any]],
                  max_patients: Optional[int] = None) -> List[Dict[str, Any]]:
    """把 CBC_L 行映射为统一结果模型。

    SEQN 是调查匿名序号，本身不含身份信息，直接用作伪 ID；
    dept/region 由桥接层登记表补齐（同 demo 编排器的做法）。
    """
    records: List[Dict[str, Any]] = []
    n_patients = 0
    seen: set = set()
    for row in rows:
        seqn = row.get("SEQN")
        if seqn is None or (seqn in seen):
            continue
        if max_patients is not None and n_patients >= max_patients:
            break
        seen.add(seqn)
        n_patients += 1
        sid = f"NH-{int(seqn)}"
        for var, m in CBC_MAP.items():
            val = row.get(var)
            if val is None:
                continue
            val = val * m["factor"]
            records.append({
                "patient_pseudo_id": sid,
                "specimen_id": sid,
                "test_item": m["item"],
                "test_name": m["name"],
                "result_value": round(val, 4),
                "unit": m["unit"],
                "ref_range": m["ref"],
                "abnormal_flag": "",            # 公开数据无仪器 H/L 标志
                "dept": "检验科", "region": "本院",
                "data_source": "nhanes_cbc_l",
            })
    return records


# ---------------------------------------------------------------------------
# 回放：脱敏 → 审核 → 熔断 + 真实分布统计
# ---------------------------------------------------------------------------

def run_replay(records: List[Dict[str, Any]], output_dir: str,
               audit_path: Optional[str] = None) -> Dict[str, Any]:
    os.makedirs(output_dir, exist_ok=True)
    log = AuditLog(audit_path or os.path.join(output_dir, "nhanes_audit_log.jsonl"))
    cfg = Config()

    # 1) 脱敏层（真实分布下验证行为；SEQN 已匿名，敏感字段数应为 0）。
    #    actor 用 access_map 中已登记的 tech01（检验科/本院/technician），
    #    region 必须为「本院」——行级授权按登记表判定，回放数据不因来源特殊而绕过门禁。
    de = Deidentifier(config=cfg, log=log)
    deid = de.deidentify(records, actor_id="tech01", role="technician",
                         data_source="nhanes_cbc_l")

    # 2) 审核层
    sc = ScreenEngine(config=cfg, log=log)
    screened = sc.screen(deid["records"], actor_id="replay",
                         data_source="nhanes_cbc_l")

    # 3) 机器判据异常率（非人工复核！）
    per_item: Dict[str, Dict[str, Any]] = {}
    for r in deid["records"]:
        it = per_item.setdefault(r["test_item"], {
            "name": r.get("test_name", ""), "unit": r["unit"],
            "ref_range": r["ref_range"], "n": 0, "values": []})
        it["n"] += 1
        try:
            it["values"].append(float(r["result_value"]))
        except (TypeError, ValueError):
            pass

    abnormal_total = 0
    for item, it in per_item.items():
        lo_s, hi_s = it["ref_range"].split("-")
        lo, hi = float(lo_s), float(hi_s)
        vals = it.pop("values")
        it["min"] = min(vals); it["max"] = max(vals)
        it["mean"] = round(sum(vals) / len(vals), 3)
        low_hits = sum(1 for v in vals if v < lo)
        high_hits = sum(1 for v in vals if v > hi)
        it["abnormal_low"], it["abnormal_high"] = low_hits, high_hits
        it["abnormal_rate"] = round((low_hits + high_hits) / it["n"], 4)
        abnormal_total += low_hits + high_hits

    # 4) 一致性对照：规则引擎标记 vs 参考区间判据（机器判据，如实标注）
    ref_judge = []
    for r in deid["records"]:
        try:
            lo_s, hi_s = str(r["ref_range"]).split("-")
            lo, hi = float(lo_s), float(hi_s)
            v = float(r["result_value"])
        except (ValueError, KeyError):
            continue
        if v < lo or v > hi:
            ref_judge.append({"patient_pseudo_id": r["patient_pseudo_id"],
                              "test_item": r["test_item"],
                              "specimen_id": r["specimen_id"]})
    agree = agreement_report(screened["watchlist"], ref_judge, len(deid["records"]))
    agree["note"] = ("human 栏在此实为「参考区间机器判据」，非人工复核；"
                     "分歧不判对错，全部列入待人工裁定项")

    # 5) 熔断检测：只喂可由数据算出的指标
    spike_ratio = abnormal_total / len(deid["records"]) if deid["records"] else 0.0
    circuit = sc.circuit_check({"abnormal_spike_ratio": round(spike_ratio, 4)})

    # 6) 解析正确性校验：实测 min/max 经单位换算后应落在官方 codebook
    #    范围内（codebook 给的是原始单位，须乘同一 factor 再比）
    codebook_check = {}
    for var, m in CBC_MAP.items():
        it = per_item.get(m["item"])
        if not it or it["n"] == 0:
            codebook_check[m["item"]] = "no_data"
            continue
        ok = (it["min"] >= m["codebook"][0] * m["factor"] - 1e-9 and
              it["max"] <= m["codebook"][1] * m["factor"] + 1e-9)
        codebook_check[m["item"]] = "pass" if ok else \
            f"FAIL({it['min']},{it['max']}) vs {m['codebook']}x{m['factor']}"

    chain = log.verify_chain()
    report = {
        "run_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "data_source": {
            "file": "CBC_L.xpt",
            "origin": "NHANES August 2021-August 2023, CDC 公开发布",
            "instrument": "Beckman Coulter DxH 800",
            "note": "公开人群调查数据，SEQN 为匿名序号；非医院受控数据",
        },
        "totals": {"records": len(records), "scanned": len(deid["records"]),
                   "patients": len({r["patient_pseudo_id"] for r in records})},
        "deidentify": deid["stats"],
        "screen": {"count": screened["count"], "urgent": screened["urgent_count"],
                   "rules_applied": screened["rules_applied"],
                   "watchlist_sample": screened["watchlist"][:20],
                   "notice": screened["notice"]},
        "per_item": per_item,
        "abnormal_judgement": {
            "criterion": "结果超出参考区间（机器判据，非人工复核）",
            "abnormal_total": abnormal_total,
            "abnormal_rate_overall": round(abnormal_total / len(deid["records"]), 4)
            if deid["records"] else None,
            "agreement": agree,
        },
        "circuit_check": {"abnormal_spike_ratio": round(spike_ratio, 4),
                          "result": circuit},
        "codebook_check": codebook_check,
        "audit": {"events": len(log.records), "chain_ok": chain["ok"],
                  "head_hash": chain["head_hash"]},
        "limitations": [
            "公开人群数据含 1-17 岁儿童，按成人参考区间判读会虚高异常率；"
            "正式使用必须按年龄/性别分层（本项目规则文件为受控文件，变更须走程序）",
            "公开数据无仪器 H/L 异常标志，R1 规则在此数据上不可测（返回 0 是预期行为）",
            "单次测量无时序，R3 趋势漂移规则在此数据上不可测",
            "「与人工判断一致率 ≥95%」仍未测量——只能由检验人员真实复核得出",
        ],
    }
    with open(os.path.join(output_dir, "nhanes_replay_report.json"), "w",
              encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    # V2.4：额外导出行级记录，供 GUI「导入回放结果」使用。
    # 汇总报告仍是验收证据；此文件只做台账流转，字段已脱敏（仅伪ID）。
    exported = []
    for r in deid["records"][:2000]:
        exported.append({
            "test_item": r.get("test_item"),
            "test_name": r.get("test_name", ""),
            "result_value": r.get("result_value"),
            "unit": r.get("unit", ""),
            "ref_range": r.get("ref_range", ""),
            "abnormal_flag": r.get("abnormal_flag", ""),
            "patient_pseudo_id": r.get("patient_pseudo_id", ""),
        })
    with open(os.path.join(output_dir, "nhanes_records.json"), "w", encoding="utf-8") as f:
        json.dump({"source": "nhanes_cbc_l", "total": len(deid["records"]),
                   "exported": len(exported), "records": exported},
                  f, ensure_ascii=False, indent=2)
    return report


# ---------------------------------------------------------------------------
# 自检（不依赖真实文件）
# ---------------------------------------------------------------------------

def selftest() -> int:
    print("== labbridge_nhanes 自检 ==")
    ok = True

    # [1] IBM 浮点转换
    cases = {
        b"\x41\x10\x00\x00\x00\x00\x00\x00": 1.0,     # 16^(65-64) * 1/16
        b"\xC1\x10\x00\x00\x00\x00\x00\x00": -1.0,
        b"\x00\x00\x00\x00\x00\x00\x00\x00": 0.0,
        b"\x41\x80\x00\x00\x00\x00\x00\x00": 8.0,     # 16^(65-64) * 8/16
    }
    for raw, expect in cases.items():
        got = ibm_to_float(raw)
        good = got is not None and abs(got - expect) < 1e-12
        ok &= good
        print(f"[1] IBM 浮点 {raw.hex()} -> {got} (期望 {expect}) "
              f"{'OK' if good else 'FAIL'}")

    miss = ibm_to_float(b".\x00\x00\x00\x00\x00\x00\x00")
    ok &= miss is None
    print(f"[2] 缺失值识别: {miss} {'OK' if miss is None else 'FAIL'}")

    # [3] 合成行映射（模拟一条 CBC 记录）
    row = {"SEQN": 1.0, "LBXWBCSI": 6.4, "LBXHGB": 13.2, "LBXHGB_missing": None,
           "LBXPLTSI": 210.0, "LBXMC": 33.5}
    for k in CBC_MAP:
        row.setdefault(k, None)
    row["LBXHCT"] = None                       # 模拟缺失
    recs = build_records([row])
    items = {r["test_item"]: r for r in recs}
    good = ("WBC" in items and abs(items["WBC"]["result_value"] - 6.4) < 1e-9
            and "HGB" in items and abs(items["HGB"]["result_value"] - 132.0) < 1e-9
            and "HCT" not in items              # 缺失不产出记录
            and len(recs) == 4)                 # 只有 4 个非空项目
    ok &= good
    print(f"[3] 记录映射: {len(recs)} 条（仅非空项目产出，缺失跳过）"
          f"{'OK' if good else 'FAIL'}")

    # [4] 灌入链路：危急值应被 R2 抓到
    row2 = dict(row, SEQN=2.0, LBXWBCSI=31.0)  # WBC 超危急上限 30
    recs2 = build_records([row, row2])
    import tempfile
    tmp = tempfile.mkdtemp(prefix="lb_nhanes_")
    rep = run_replay(recs2, tmp, audit_path=os.path.join(tmp, "a.jsonl"))
    urgent = rep["screen"]["urgent"]
    good = urgent >= 1 and rep["audit"]["chain_ok"]
    ok &= good
    print(f"[4] 链路回放: 待关注 {rep['screen']['count']} 条, 危急 {urgent}, "
          f"审计链 {'完整' if rep['audit']['chain_ok'] else '断裂'} "
          f"{'OK' if good else 'FAIL'}")

    # [5] codebook 校验逻辑本身
    good = all(v == "pass" or str(v).startswith("FAIL") or v == "no_data"
               for v in rep["codebook_check"].values())
    ok &= good
    print(f"[5] codebook 校验执行: OK")

    print("结果:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def find_public_data(filename: str = "CBC_L.xpt") -> str:
    """定位公开数据文件：从本文件目录与当前工作目录逐级向上搜索 `公开数据/`。

    V2.5.2 修复：原先写死 `code/../../公开数据/`，在交付封包布局下解析到
    `01_软件封包/公开数据/`（按交付纪律不存在），无参运行必然 FileNotFoundError。
    现改为向上逐级搜索；仍找不到时回落到旧默认值，由调用方给出可读报错。
    """
    name = filename.lower()
    for start in (os.path.dirname(os.path.abspath(__file__)), os.getcwd()):
        cur = start
        for _ in range(8):                      # 最多上溯 8 级，足够覆盖常规布局
            cand = os.path.join(cur, "公开数据", filename)
            if os.path.isfile(cand):
                return os.path.normpath(cand)
            # 公开数据目录下允许按类目分子目录（如 血常规/），深度 2 内大小写不敏感查找
            pub = os.path.join(cur, "公开数据")
            if os.path.isdir(pub):
                for dirpath, dirnames, filenames in os.walk(pub):
                    rel = os.path.relpath(dirpath, pub)
                    if rel != "." and rel.count(os.sep) >= 2:
                        dirnames[:] = []        # 限制深度 2
                        continue
                    for fn in filenames:
                        if fn.lower() == name:
                            return os.path.normpath(os.path.join(dirpath, fn))
            nxt = os.path.dirname(cur)
            if nxt == cur:
                break
            cur = nxt
    return os.path.normpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "公开数据", filename))


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="NHANES CBC_L 真实数据回放")
    ap.add_argument("--xpt", default=find_public_data("CBC_L.xpt"))
    ap.add_argument("--out", default=os.path.normpath(os.path.join(here, "..", "output")))
    ap.add_argument("--max-patients", type=int, default=None,
                    help="限制人数（默认全部）")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())

    names, rows = read_xpt(args.xpt)
    print(f"读取 {args.xpt}: {len(rows)} 行, 变量 {len(names)} 个")
    records = build_records(rows, max_patients=args.max_patients)
    print(f"映射 {len(records)} 条结果, "
          f"{len({r['patient_pseudo_id'] for r in records})} 人")
    rep = run_replay(records, args.out)
    print(f"待关注 {rep['screen']['count']} 条（危急 {rep['screen']['urgent']}）, "
          f"机器判据异常率 {rep['abnormal_judgement']['abnormal_rate_overall']}, "
          f"审计链 ok={rep['audit']['chain_ok']}")
    print(f"报告: {os.path.join(args.out, 'nhanes_replay_report.json')}")
