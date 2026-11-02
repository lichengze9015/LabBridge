#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LabBridge 证据报告生成器 —— 替代 anthropics/skills 中 source-available 的 docx skill

反溯说明 / Provenance
---------------------
依据 **OOXML / ECMA-376 公开标准** 与 MIT 许可的 python-docx 独立编写。

**未参考 anthropics/skills 中 skills/docx、skills/pdf、skills/pptx、skills/xlsx
的任何内容。** 那四个 skill 在仓库 README 中明确标注为
「source-available, not open source」，只能看不能用——照搬会把自己的封包
变成一个授权不明的派生品。

替代路径很清楚：生成 docx 这件事本身没有任何门槛，
    python-docx   MIT      （写 .docx）
    openpyxl      MIT      （写 .xlsx，如需风险登记表）
    python-pptx   MIT      （写 .pptx，如需汇报页）
都是干净的 MIT，功能覆盖我们所需。

输出遵循文档集 05 / 08：
    - 报告头含版本号、生成时间、内容 SHA-256（可锚定证据链）
    - 表格化风险清单与验收基线
    - 末尾附不适用声明

用法:
    python labbridge_report.py --selftest
    python labbridge_report.py --type risk --output 敏感数据接入专项风险评估报告.docx
"""

import sys
import os
import json
import hashlib
import datetime
import argparse
from typing import Any, Dict, List, Optional

try:
    import docx
    from docx.shared import Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    HAS_DOCX = True
except ImportError:
    HAS_DOCX = False

VERSION = "1.0.0"


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _sha256(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------------------
# 报告内容（数据外置，便于替换为你自己的内审结论）
# ---------------------------------------------------------------------------

RISK_ROWS: List[List[str]] = [
    ["AI 幻觉风险", "AI 生成虚假文档、条款错配，造成外审不符合项",
     "AI 输出对标标准原文，人工逐条复核，留存条款比对记录", "中", "已部署"],
    ["代码/Agent 权限风险", "提示词注入、越权访问、硬编码密钥，文档泄露",
     "收缩权限，输入过滤，定期安全审计", "高", "已部署"],
    ["数据风险", "敏感数据未分级管控直接上线引发合规问题",
     "三级梯度上线，涉密数据不进入 AI 平台，做好脱敏", "高", "已部署"],
    ["版本风险", "知识库无版本管理，迭代无修改痕迹",
     "全部文档分配版本号，留存旧版本，离线双备份", "低", "已部署"],
    ["沉没成本风险", "业务逻辑硬绑定 AI 平台，平台迭代导致方案失效",
     "知识库模板离线独立存储，工作流可导出，支持跨平台迁移", "中", "已部署"],
]

BASELINE_ROWS: List[List[str]] = [
    ["条款匹配准确度", "≥ 90%", "建议值，按场景校准", "待实测"],
    ["脱敏正确率", "100%", "场景标准", "待实测"],
    ["全程日志留痕率", "100%", "场景标准", "待实测"],
    ["连续抓取标本数", "≥ 50 份", "场景标准", "待实测"],
    ["结果完整率", "≥ 99%", "场景标准", "待实测"],
    ["异常标记与人工一致率", "≥ 95%", "场景标准", "待实测"],
]

NOT_APPLICABLE = [
    "本 Demo 为单人自研方法论验证原型，仅用于作品集，不是生产系统，不对外承接真实业务。",
    "代码、Agent 配置由 AI 生成，仅演示逻辑，不做正式生产代码缺陷闭环修复。",
    "API 端口预留但默认关闭，不真实对接业务/MES/LIMS。",
    "硬件现场部署、现场培训相关条款不适用。",
    "政策补贴比例、金额与案例均引自 AI 推演，立项申报前需以最新官方文件核实。",
]


# ---------------------------------------------------------------------------
# 生成器
# ---------------------------------------------------------------------------

def _h(doc, text: str, level: int = 1):
    p = doc.add_heading(text, level=level)
    return p


def _table(doc, headers: List[str], rows: List[List[str]]):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Light Grid Accent 1" if "Light Grid Accent 1" in [
        s.name for s in doc.styles] else "Table Grid"
    for i, h in enumerate(headers):
        cell = t.rows[0].cells[i]
        cell.text = h
        for r in cell.paragraphs[0].runs:
            r.font.bold = True
    for row in rows:
        cells = t.add_row().cells
        for i, v in enumerate(row):
            cells[i].text = str(v)
    return t


def build_report(rtype: str = "risk",
                 output: str = "labbridge_report.docx",
                 meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not HAS_DOCX:
        raise RuntimeError("需要 python-docx：pip install python-docx  (MIT)")

    meta = meta or {}
    doc = docx.Document()

    # 封面区
    title = doc.add_heading(
        "敏感数据接入专项风险评估报告" if rtype == "risk"
        else "公共/非敏感数据场景测试报告", level=0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = sub.add_run("LabBridge 检验数据桥接 Demo · 证据包交付物")
    run.font.size = Pt(11)
    run.font.color.rgb = RGBColor(0x60, 0x60, 0x60)

    _table(doc, ["项目", "值"], [
        ["文档集版本", meta.get("docset_version", "V1.0")],
        ["报告生成器", f"labbridge_report/{VERSION}"],
        ["生成时间", _now()],
        ["适配标准", "ISO 9001 / ISO/IEC 42001:2023"],
        ["责任人", meta.get("owner", "AI 边界安全官")],
    ])

    doc.add_paragraph()

    # 一、目的与范围
    _h(doc, "一、目的与范围", 1)
    doc.add_paragraph(
        "本报告用于记录 LabBridge Demo 在敏感数据接入前的风险识别、控制措施与残余风险判定，"
        "作为阶段三的评审依据。阶段三评审未通过，不得进入阶段四（受控接入真实敏感数据实测）。")
    doc.add_paragraph("管控总原则：人定规则、机器执行、人审例外。", style="Intense Quote")

    # 二、风险清单
    _h(doc, "二、AI 与体系通用风险清单", 1)
    _table(doc, ["风险类别", "风险描述", "管控措施", "等级", "状态"], RISK_ROWS)
    doc.add_paragraph("风险值 R = 可能性 L × 后果 C；R≥6 为高风险，须强制人工终审并记录残余风险。")

    # 三、敏感数据专项
    _h(doc, "三、敏感数据接入专项风险", 1)
    _table(doc, ["#", "风险", "控制措施", "残余风险"], [
        ["1", "数据泄露", "字段掩码、最小暴露面、国密传输", "待评估"],
        ["2", "模型留存数据", "底座选型规则；敏感场景评估私有化部署", "待评估"],
        ["3", "会话污染", "会话隔离、会话自动清理", "待评估"],
        ["4", "敏感信息外溢", "访问白名单、输入输出过滤、二次复核", "待评估"],
        ["5", "幻觉生成虚假体系证据", "输出对标原文、人工逐条复核、留存比对记录", "待评估"],
    ])

    # 四、验收基线
    _h(doc, "四、量化验收基线", 1)
    _table(doc, ["指标", "基线", "口径", "当前状态"], BASELINE_ROWS)

    # 五、人在回路与留痕
    _h(doc, "五、人在回路与证据留痕", 1)
    for t in [
        "低风险只读操作：自动执行 + 事后抽样审计。",
        "中风险操作：触发人工审批。",
        "高风险不可逆操作：强制人工审批，禁止全自动；审批超时默认拒绝。",
        "审批卡须携带动作计划、预期影响、风险提示、回滚方案四要素。",
        "每笔授权判断与工具调用留痕：谁、什么上下文、基于哪条策略、读取字段何种形态、是否人工介入。",
        "规则文件、例外审批记录、运行时访问日志各自锚定时间戳与哈希。",
    ]:
        doc.add_paragraph(t, style="List Bullet")

    # 六、不适用声明
    _h(doc, "六、不适用声明", 1)
    for t in NOT_APPLICABLE:
        doc.add_paragraph(t, style="List Bullet")

    # 证据锚定
    _h(doc, "七、证据锚定", 1)
    payload = {
        "rtype": rtype,
        "risk_rows": RISK_ROWS,
        "baseline_rows": BASELINE_ROWS,
        "generated_at": _now(),
        "generator": f"labbridge_report/{VERSION}",
    }
    digest = _sha256(payload)
    _table(doc, ["项", "值"], [
        ["内容 SHA-256", digest],
        ["生成时间", _now()],
        ["生成器版本", VERSION],
    ])
    doc.add_paragraph(
        "本报告内容哈希可与其他证据文件一同锚定，用于证明「规则在某时刻被批准并被实际执行」。")

    doc.save(output)
    return {"output": os.path.abspath(output), "sha256": digest,
            "generated_at": _now(), "version": VERSION}


def selftest() -> int:
    print("== labbridge_report 自检 ==")
    if not HAS_DOCX:
        print("python-docx 未安装，跳过（pip install python-docx，MIT）")
        return 1
    out = "selftest_report.docx"
    r = build_report("risk", out)
    print(f"[1] 生成 {r['output']}")
    print(f"[2] SHA-256 = {r['sha256'][:32]}...")
    exists = os.path.exists(out)
    size = os.path.getsize(out) if exists else 0
    print(f"[3] 文件大小 = {size} bytes")
    ok = exists and size > 10000
    print("\n结果:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="LabBridge 证据报告生成器")
    ap.add_argument("--type", default="risk", choices=["risk", "test"])
    ap.add_argument("--output", default="labbridge_report.docx")
    ap.add_argument("--owner", default="AI 边界安全官")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest())
    r = build_report(a.type, a.output, {"owner": a.owner})
    print(json.dumps(r, ensure_ascii=False, indent=2))
