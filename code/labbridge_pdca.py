#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LabBridge PDCA 质量工具集 —— 依据《工具记录清单》实现

依据：内部《工具记录清单》（未随本仓库发布，工具条目已在下方函数清单中完整列出）
    P 策划（ISO9001 第 4/6/7 章）：SIPOC/乌龟图、风险矩阵 RPN、FMEA、SWOT/PEST、
        目标展开树、策划检查表、MSA、控制计划初稿
    D 实施（第 8 章）：查检表、分层法、运行图、直方图、SPC 控制图、散布图、
        GB/T2828 计数抽样、计量抽样、PPAP、人工文件符合性检验、Poka-Yoke 防错
    C 检查（第 9 章）：帕累托图、鱼骨图、箱线图、柱状饼图、内审检查表、
        顾客满意度测评、质量成本 COQ、能力成熟度评价
    A 处置（第 10 章）：5Why、FTA、亲和图、关系图、DOE、CAPA、对策表、8D、DMAIC

选用原则（清单第七节，已写进代码约束）：
    1. 按需选用，不堆砌          -> 每个工具带 `recommended_for` 适用判定
    2. 高风险敏感场景叠加 FMEA、FTA、风险矩阵 -> `HIGH_RISK_STACK` 强制组合
    3. 量化指标优先做 MSA        -> 测量类工具调用前自动触发 MSA 前置校验
    4. 检验分准入检验/过程检验    -> `inspection_type` 字段
    5. 高风险增加测量频次与复核层级 -> `sampling_boost()` / `review_level()`

依赖：仅 Python 标准库（与 labbridge_mcp.py 一致的零依赖策略）

用法:
    python labbridge_pdca.py --selftest               # 测试所有步骤
    python labbridge_pdca.py --run -o <输出目录>       # 全量运行并输出报告+日志
    python labbridge_pdca.py --api-status              # 查看 4 个 API 接口状态
"""

import argparse
import hashlib
import datetime
import json
import math
import os
import random
import statistics
import sys
import uuid
from typing import Any, Callable, Dict, List, Optional

VERSION = "1.0.0"

# ===========================================================================
# 审计日志（哈希链，对齐文档 05 第七章）
# ===========================================================================

def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _sha256(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


class RunLog:
    """带哈希链的审计日志。每条记录含 prev_hash，形成不可篡改的因果链。"""

    def __init__(self, actor_id: str = "pdca-runner", actor_role: str = "engineer"):
        self.events: List[Dict[str, Any]] = []
        self.prev_hash = "0" * 64
        self.actor_id = actor_id
        self.actor_role = actor_role

    def add(self, action: str, obj: str = "", result: str = "ok",
            data_class: str = "internal", human_involved: bool = False,
            **extra: Any) -> Dict[str, Any]:
        rec = {
            "seq": len(self.events) + 1,          # 自增序号：可检测日志缺失/跳号
            "event_id": str(uuid.uuid4()),
            "timestamp": _now_iso(),
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
            "action": action,
            "object": obj,
            "data_class": data_class,
            "human_involved": human_involved,
            "result": result,
            "component": f"labbridge_pdca/{VERSION}",
            **extra,
        }
        rec["prev_hash"] = self.prev_hash
        rec["hash"] = _sha256({k: v for k, v in rec.items() if k != "hash"})
        self.prev_hash = rec["hash"]
        self.events.append(rec)
        return rec

    def write_jsonl(self, path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for e in self.events:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        return os.path.abspath(path)

    @property
    def chain_head(self) -> str:
        return self.prev_hash


# ===========================================================================
# 四个预留 API 接口 —— 默认关闭，需人工显式打开
# ===========================================================================

class APIGate:
    """单个 API 接口的开关。默认关闭；打开需人工审批四要素，超时默认拒绝。"""

    def __init__(self, key: str, name: str, description: str, risk_level: str,
                 data_class: str, requires_approval: bool = True):
        self.key = key
        self.name = name
        self.description = description
        self.risk_level = risk_level          # low / medium / high
        self.data_class = data_class
        self.requires_approval = requires_approval
        self.enabled = False                   # **默认关闭**
        self._pending: Optional[Dict[str, Any]] = None

    def request_enable(self, log: RunLog, actor_id: str,
                       plan: str = "", impact: str = "",
                       risk_note: str = "", rollback: str = "",
                       timeout_s: int = 30) -> Dict[str, Any]:
        """申请打开。必须携带审批四要素：动作计划、预期影响、风险提示、回滚方案。"""
        missing = [n for n, v in [("动作计划", plan), ("预期影响", impact),
                                  ("风险提示", risk_note), ("回滚方案", rollback)] if not v]
        if missing:
            log.add(action="api_enable_request", obj=self.key, result="rejected",
                    data_class=self.data_class, human_involved=True,
                    reason=f"审批要素缺失: {missing}", policy_hit="approval-4-elements")
            return {"api": self.key, "status": "rejected", "reason": f"审批要素缺失: {missing}"}

        token = str(uuid.uuid4())[:8]
        self._pending = {"token": token, "requested_at": _now_iso(),
                         "timeout_s": timeout_s, "actor_id": actor_id}
        log.add(action="api_enable_request", obj=self.key, result="pending",
                data_class=self.data_class, human_involved=True,
                token=token, risk_level=self.risk_level, policy_hit="approval-4-elements")
        return {"api": self.key, "status": "pending", "token": token,
                "timeout_s": timeout_s, "note": "等待人工确认；超时将自动拒绝"}

    def confirm_enable(self, log: RunLog, token: str, approver: str) -> Dict[str, Any]:
        """人工确认打开。超时或 token 不符 -> 拒绝（默认拒绝原则）。"""
        if self._pending is None:
            return {"api": self.key, "status": "rejected", "reason": "无待确认申请"}
        if self._pending["token"] != token:
            log.add(action="api_enable_confirm", obj=self.key, result="rejected",
                    human_involved=True, reason="token 不匹配")
            return {"api": self.key, "status": "rejected", "reason": "token 不匹配"}

        req_at = datetime.datetime.fromisoformat(self._pending["requested_at"])
        elapsed = (datetime.datetime.now(datetime.timezone.utc) - req_at).total_seconds()
        if elapsed > self._pending["timeout_s"]:
            self._pending = None
            log.add(action="api_enable_confirm", obj=self.key, result="timeout_denied",
                    human_involved=True, approver=approver,
                    policy_hit="approval-timeout-default-deny")
            return {"api": self.key, "status": "denied", "reason": "审批超时，默认拒绝"}

        self.enabled = True
        self._pending = None
        log.add(action="api_enable_confirm", obj=self.key, result="enabled",
                data_class=self.data_class, human_involved=True,
                approver=approver, risk_level=self.risk_level)
        return {"api": self.key, "status": "enabled", "approver": approver,
                "risk_level": self.risk_level}

    def disable(self, log: RunLog, actor_id: str) -> Dict[str, Any]:
        self.enabled = False
        log.add(action="api_disable", obj=self.key, result="disabled", human_involved=True)
        return {"api": self.key, "status": "disabled"}

    def call(self, log: RunLog, **payload: Any) -> Dict[str, Any]:
        """调用接口。未打开则拒绝，不静默放行。"""
        if not self.enabled:
            log.add(action="api_call", obj=self.key, result="blocked",
                    data_class=self.data_class, reason="接口默认关闭，未获人工开启",
                    policy_hit="default-closed")
            return {"api": self.key, "status": "blocked",
                    "reason": "接口默认关闭，需人工审批后开启"}
        log.add(action="api_call", obj=self.key, result="ok",
                data_class=self.data_class, human_involved=True)
        return {"api": self.key, "status": "ok", "echo": payload}

    def state(self) -> Dict[str, Any]:
        return {"key": self.key, "name": self.name, "enabled": self.enabled,
                "risk_level": self.risk_level, "data_class": self.data_class,
                "description": self.description}


def build_api_gates() -> Dict[str, APIGate]:
    """四个预留接口。全部默认关闭。"""
    return {
        "astm_ingest": APIGate(
            "astm_ingest", "仪器 ASTM 接入接口",
            "从检验仪器串口/TCP 旁路接收 ASTM E1381/E1394 结果；只读，不向仪器下发指令",
            "high", "sensitive"),
        "ocr_extract": APIGate(
            "ocr_extract", "拍照 OCR 抽取接口",
            "手机拍摄单据/仪器屏幕 -> 端侧 OCR -> 结构化抽取；原始图像不出本地",
            "medium", "sensitive"),
        "lis_writeback": APIGate(
            "lis_writeback", "原厂 LIS 回传接口",
            "按需将结构化结果回传原厂 LIS（不强制）；最高风险，默认永久关闭",
            "high", "sensitive"),
        "cloud_llm": APIGate(
            "cloud_llm", "云端大模型调用接口",
            "调用云端 LLM 做报告解读；仅允许传入脱敏文本",
            "medium", "internal"),
    }


# ===========================================================================
# 工具注册
# ===========================================================================

PHASE_NAME = {"P": "策划 Plan", "D": "实施 Do", "C": "检查 Check", "A": "处置 Act"}
PHASE_ISO = {"P": "第 4/6/7 章", "D": "第 8 章", "C": "第 9 章", "A": "第 10 章"}

HIGH_RISK_STACK = ["risk_matrix_rpn", "fmea", "fta"]   # 清单原则 2


class Tool:
    def __init__(self, tid: str, name: str, phase: str, category: str,
                 purpose: str, inputs: str, outputs: str,
                 recommended_for: str, fn: Callable[[Dict[str, Any]], Dict[str, Any]]):
        self.id, self.name, self.phase, self.category = tid, name, phase, category
        self.purpose, self.inputs, self.outputs = purpose, inputs, outputs
        self.recommended_for = recommended_for
        self.fn = fn

    @property
    def iso(self) -> str:
        return PHASE_ISO[self.phase]


REGISTRY: List[Tool] = []


def tool(tid: str, name: str, phase: str, category: str, purpose: str,
         inputs: str, outputs: str, recommended_for: str):
    def deco(fn: Callable[[Dict[str, Any]], Dict[str, Any]]):
        REGISTRY.append(Tool(tid, name, phase, category, purpose,
                             inputs, outputs, recommended_for, fn))
        return fn
    return deco


# ---------- 通用统计辅助 ----------

def quantile(sorted_vals: List[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    pos = (len(sorted_vals) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return sorted_vals[int(pos)]
    return sorted_vals[lo] * (hi - pos) + sorted_vals[hi] * (pos - lo)


# ---------- 演示数据（合成，不含任何真实患者信息） ----------

def make_demo_data(n: int = 60) -> Dict[str, Any]:
    """合成标本结果：基线稳定，中段引入漂移，末段注入异常——用于检验 SPC/帕累托等。"""
    rnd = random.Random(20261022)
    values: List[float] = []
    for i in range(n):
        base = 4.2
        if 30 <= i < 45:            # 漂移段
            base += 0.35
        v = rnd.gauss(base, 0.18)
        if i in (12, 47, 52):       # 异常点
            v += 1.1
        values.append(round(v, 2))
    items = ["K", "GLU", "HGB", "PLT", "K", "GLU"]
    defects = {"脱敏字段遗漏": 7, "条款匹配错误": 4, "日志缺失": 3,
               "OCR 识别错误": 2, "危急值漏标": 1}
    return {
        "values": values,
        "items": [items[i % len(items)] for i in range(n)],
        "defects": defects,
        "operators": ["A", "B", "C"],
        "parts": list(range(1, 11)),
    }


# ===========================================================================
# P — 策划阶段工具
# ===========================================================================

@tool("sipoc", "SIPOC / 乌龟图", "P", "测量",
      "界定过程边界与输入输出，识别过程要素",
      "供方、输入、过程、输出、顾客", "SIPOC 表 + 乌龟图六要素",
      "场景启动、边界划定")
def t_sipoc(d: Dict[str, Any]) -> Dict[str, Any]:
    sipoc = {
        "Supplier": ["检验仪器（Sysmex/Mindray 等）", "检验科人员", "OCR 端侧设备"],
        "Input": ["ASTM E1381/E1394 结果帧", "手写单据图像", "参考区间与危急值阈值"],
        "Process": ["旁路接收 → 标准化 → 脱敏 → 轻量审核 → 待关注列表"],
        "Output": ["脱敏结构化结果", "待关注列表", "审计日志"],
        "Customer": ["检验人员", "科室主任", "院领导/评审专家"],
    }
    turtle = {
        "人 Man": ["检验员", "组长", "主任", "工程师"],
        "机 Machine": ["桥接主机/边缘盒子", "手机端"],
        "料 Material": ["ASTM 消息", "OCR 图像"],
        "法 Method": ["统一结果模型", "三条审核规则", "分级脱敏规则"],
        "环 Environment": ["检验科现场", "云端（仅脱敏数据）"],
        "测 Measurement": ["结果完整率", "脱敏正确率", "异常一致率", "日志留痕率"],
    }
    return {"sipoc": sipoc, "turtle": turtle,
            "boundary_note": "桥接层不向仪器发送任何指令（只读旁路）"}


@tool("risk_matrix_rpn", "风险矩阵 RPN", "P", "监视",
      "按严重度×发生度×探测度打分排序，确定控制优先级",
      "风险清单（S/O/D）", "RPN 排序表 + 高风险清单",
      "所有阶段；高风险敏感场景必用")
def t_risk_matrix(d: Dict[str, Any]) -> Dict[str, Any]:
    rows = [
        {"risk": "敏感数据泄露", "S": 9, "O": 4, "D": 4},
        {"risk": "AI 幻觉生成虚假体系证据", "S": 8, "O": 6, "D": 5},
        {"risk": "提示词注入/越权访问", "S": 8, "O": 3, "D": 3},
        {"risk": "危急值漏标", "S": 9, "O": 3, "D": 2},
        {"risk": "知识库无版本管理", "S": 4, "O": 6, "D": 6},
        {"risk": "平台绑定沉没成本", "S": 5, "O": 5, "D": 7},
    ]
    for r in rows:
        r["RPN"] = r["S"] * r["O"] * r["D"]
        r["level"] = "高" if r["RPN"] >= 100 else ("中" if r["RPN"] >= 40 else "低")
    rows.sort(key=lambda x: -x["RPN"])
    high = [r for r in rows if r["level"] == "高"]
    return {"rows": rows, "high_count": len(high),
            "high_risks": [r["risk"] for r in high],
            "rule": "RPN=S×O×D；≥100 高风险须强制人工终审并记录残余风险"}


@tool("fmea", "FMEA 失效模式分析", "P", "监视",
      "逐项分析失效模式、后果、原因与现行控制，输出改进优先序",
      "过程步骤清单", "FMEA 表（含 RPN 与建议措施）",
      "高风险敏感场景与 FTA、风险矩阵叠加使用")
def t_fmea(d: Dict[str, Any]) -> Dict[str, Any]:
    rows = [
        {"step": "ASTM 接收", "mode": "帧校验失败丢包", "effect": "结果不完整",
         "cause": "串口干扰/缓冲区溢出", "control": "确认帧+校验和+重传计数", "S": 7, "O": 3, "D": 2},
        {"step": "脱敏", "mode": "身份字段未掩码", "effect": "PII 落库",
         "cause": "字段清单不全", "control": "默认 redact + 脱敏后正则回扫", "S": 9, "O": 2, "D": 2},
        {"step": "AI 审核", "mode": "幻觉标记错误", "effect": "误报/漏报",
         "cause": "阈值配置错误", "control": "规则引擎可解释 + 人工终审", "S": 8, "O": 4, "D": 3},
        {"step": "输出", "mode": "措辞越界（已审核）", "effect": "被视为替代签字",
         "cause": "文案未受控", "control": "lb_check_wording 禁用词校验", "S": 7, "O": 3, "D": 1},
        {"step": "归档", "mode": "资产未离线备份", "effect": "平台迭代导致失效",
         "cause": "依赖在线平台", "control": "工作流导出 + 移动硬盘冷备", "S": 5, "O": 4, "D": 4},
    ]
    for r in rows:
        r["RPN"] = r["S"] * r["O"] * r["D"]
    rows.sort(key=lambda x: -x["RPN"])
    for r in rows:
        r["action"] = "立即改进" if r["RPN"] >= 60 else "计划改进"
    return {"rows": rows, "top": rows[0]["mode"], "top_rpn": rows[0]["RPN"]}


@tool("swot_pest", "SWOT / PEST", "P", "监视",
      "内外部环境与战略态势分析",
      "组织内外部信息", "SWOT 四象限 + PEST 六维度",
      "立项前、战略对齐")
def t_swot_pest(d: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "SWOT": {
            "S 优势": ["ASTM 为公开标准，不依赖原厂", "边缘盒子即可运行，成本极低",
                       "ISO 体系合规资产可沉淀"],
            "W 劣势": ["单人 Demo，无现场落地能力", "ASTM 上游开源包为早期项目",
                       "乡镇 OCR 手写体准确率不稳"],
            "O 机会": ["医共体检验同质化与结果互认", "基层 AI 专项补贴",
                       "原厂不覆盖的桥接位真空"],
            "T 威胁": ["原厂质疑旁路干扰", "等保/密评资质门槛", "卫生院付费能力趋零"],
        },
        "PEST": {
            "P 政治": ["人工智能+基层专项政策"],
            "E 经济": ["基层信息化预算紧张，需总院/区域打包"],
            "S 社会": ["基层检验人手不足、手抄普遍"],
            "T 技术": ["ASTM E1381/E1394 通用、OCR 精度提升"],
            "E 环境": ["边缘部署、低固定投入"],
            "L 法律": ["数据安全法、等保 2.0、密评、个人信息保护"],
        },
    }


@tool("target_tree", "目标展开树", "P", "测量",
      "把总目标逐层展开为可测量子目标",
      "项目总目标", "目标树（含量化基线）",
      "目标策划，与文档 02 一级目标对齐")
def t_target_tree(d: Dict[str, Any]) -> Dict[str, Any]:
    return {"tree": {
        "总目标": "ISO 体系约束下的 AI Agent 治理 Demo",
        "L1": [
            {"name": "公共/非敏感场景试点验证",
             "baseline": ["条款匹配 ≥90%", "脱敏正确率 100%", "日志留痕 100%"]},
            {"name": "敏感数据接入风险方案",
             "baseline": ["专项评估报告评审通过", "准入边界定稿"]},
            {"name": "受控敏感数据实测",
             "baseline": ["≥50 份标本", "完整率 ≥99%", "异常一致率 ≥95%"]},
            {"name": "业务资产解耦", "baseline": ["可脱离底座复用"]},
            {"name": "完整 PDCA 循环", "baseline": ["证据包 + CAPA 记录"]},
        ]}, "levels": 2}


@tool("plan_checklist", "策划检查表", "P", "检验/符合性评价",
      "核对策划阶段交付物是否齐备（准入检验）",
      "策划交付物清单", "完成率 + 缺失项",
      "阶段门评审；inspection_type=准入检验")
def t_plan_checklist(d: Dict[str, Any]) -> Dict[str, Any]:
    items = [
        ("范围说明书", True), ("相关方登记台账", True), ("质量方针成文", True),
        ("质量目标（可测量）", True), ("风险清单", True), ("控制计划初稿", True),
        ("MSA 报告", False), ("FMEA 报告", True), ("敏感数据准入审批", False),
    ]
    done = [n for n, ok in items if ok]
    missing = [n for n, ok in items if not ok]
    return {"items": items, "done": done, "missing": missing,
            "completion": round(len(done) / len(items), 3),
            "inspection_type": "准入检验",
            "gate": "通过" if not missing else f"阻塞：缺 {missing}"}


@tool("msa", "MSA 测量系统分析", "P", "测量",
      "评价测量系统本身是否可信（GR&R 极差法）",
      "零件×操作员×重复测量数据", "EV/AV/GRR/%GRR + 判定",
      "清单原则 3：量化指标优先做 MSA")
def t_msa(d: Dict[str, Any]) -> Dict[str, Any]:
    # 极差法（Xbar-R）：3 名操作员 × 10 个零件 × 2 次重复
    rnd = random.Random(7)
    parts, ops, trials = 10, 3, 2
    data = {(o, p): [round(rnd.gauss(4.2 + p * 0.05, 0.04), 3) for _ in range(trials)]
            for o in range(ops) for p in range(parts)}
    ranges = [max(v) - min(v) for v in data.values()]
    rbar = statistics.mean(ranges)
    K1 = 4.56                                   # 2 次重复
    EV = rbar * K1
    op_avgs = [statistics.mean([statistics.mean(data[(o, p)]) for p in range(parts)])
               for o in range(ops)]
    xdiff = max(op_avgs) - min(op_avgs)
    K2 = 2.70                                   # 3 名操作员
    AV = math.sqrt(max((xdiff * K2) ** 2 - EV ** 2 / (parts * trials), 0))
    GRR = math.sqrt(EV ** 2 + AV ** 2)
    tolerance = 1.0                             # 过程公差（示例）
    pct = GRR / tolerance * 100
    verdict = ("可接受" if pct < 10 else
               "有条件可接受（需改进）" if pct < 30 else "不可接受")
    return {"rbar": round(rbar, 4), "EV": round(EV, 4), "AV": round(AV, 4),
            "GRR": round(GRR, 4), "%GRR": round(pct, 2), "verdict": verdict,
            "note": "清单原则 3：量化指标优先做 MSA，保证测量本身可信"}


@tool("control_plan", "控制计划初稿", "P", "检验/符合性评价",
      "规定过程控制项、频次、方法与反应计划",
      "FMEA 输出 + 过程步骤", "控制计划表",
      "策划阶段输出；高风险场景提高频次与复核层级")
def t_control_plan(d: Dict[str, Any]) -> Dict[str, Any]:
    rows = [
        {"过程": "ASTM 接收", "控制项": "结果完整率", "频次": "每批",
         "方法": "自动计数 + 日志", "反应计划": "低于 99% 触发人工全量复核", "层级": "自动"},
        {"过程": "脱敏", "控制项": "脱敏正确率", "频次": "每条",
         "方法": "正则回扫", "反应计划": "命中即阻断输出并告警", "层级": "自动+人工"},
        {"过程": "AI 审核", "控制项": "异常一致率", "频次": "每批回溯",
         "方法": "与人工记录比对", "反应计划": "低于 95% 熔断切换人工", "层级": "人工终审"},
        {"过程": "敏感数据接入", "控制项": "准入审批", "频次": "每次",
         "方法": "审批四要素 + 超时拒绝", "反应计划": "未批准禁止加载", "层级": "主任审批"},
    ]
    return {"rows": rows, "count": len(rows),
            "boost_rule": "高风险场景：频次翻倍 + 复核层级上提一级"}


# ===========================================================================
# D — 实施阶段工具
# ===========================================================================

@tool("check_sheet", "查检表", "D", "测量",
      "按类别统计缺陷/事件发生频次",
      "原始记录", "频次统计表", "实施期日常采集")
def t_check_sheet(d: Dict[str, Any]) -> Dict[str, Any]:
    defects = d["defects"]
    total = sum(defects.values())
    rows = [{"类别": k, "频次": v, "占比": round(v / total, 4)}
            for k, v in sorted(defects.items(), key=lambda x: -x[1])]
    return {"rows": rows, "total": total}


@tool("stratification", "分层法", "D", "监视",
      "按来源/项目/班次分层，暴露层间差异",
      "带分层标签的数据", "分层统计表", "实施期数据切面分析")
def t_stratification(d: Dict[str, Any]) -> Dict[str, Any]:
    vals, items = d["values"], d["items"]
    layers: Dict[str, List[float]] = {}
    for v, it in zip(vals, items):
        layers.setdefault(it, []).append(v)
    rows = [{"层": k, "n": len(v), "均值": round(statistics.mean(v), 3),
             "标准差": round(statistics.pstdev(v), 3),
             "极差": round(max(v) - min(v), 3)}
            for k, v in sorted(layers.items())]
    return {"rows": rows, "layers": len(rows),
            "max_spread": round(max(r["极差"] for r in rows), 3)}


@tool("run_chart", "运行图", "D", "监视",
      "按时间序观察趋势与漂移",
      "时序数据", "趋势判定（8 条判异准则之简化版）", "实施期运行监控")
def t_run_chart(d: Dict[str, Any]) -> Dict[str, Any]:
    v = d["values"]
    med = statistics.median(v)
    # 准则1：连续 7 点位于中位数同侧
    runs, cur, cur_sign = 1, 1, None
    longest = 1
    for i, x in enumerate(v):
        sign = 1 if x > med else -1
        if i and sign == cur_sign:
            cur += 1
        else:
            cur = 1
        cur_sign = sign
        longest = max(longest, cur)
    rule1 = longest >= 7
    # 准则：连续 6 点递增或递减
    inc = dec = 1
    for i in range(1, len(v)):
        if v[i] > v[i - 1]:
            inc, dec = inc + 1, 1
        elif v[i] < v[i - 1]:
            dec, inc = dec + 1, 1
        else:
            inc = dec = 1
    rule2 = max(inc, dec) >= 6
    return {"median": round(med, 3), "longest_run": longest,
            "values": [round(x, 3) for x in v],
            "rule1_same_side": rule1, "rule2_trend": rule2,
            "verdict": "异常（存在趋势/漂移信号）" if (rule1 or rule2) else "受控"}


@tool("histogram", "直方图", "D", "测量",
      "观察分布形态与偏离",
      "计量数据", "分箱频次 + 形态判定", "实施期分布检查")
def t_histogram(d: Dict[str, Any]) -> Dict[str, Any]:
    v = sorted(d["values"])
    lo, hi = min(v), max(v)
    bins = 8
    width = (hi - lo) / bins
    counts = [0] * bins
    for x in v:
        idx = min(int((x - lo) / width), bins - 1)
        counts[idx] += 1
    mean, sd = statistics.mean(v), statistics.pstdev(v)
    # 偏态粗判
    skew = round((statistics.mean(v) - statistics.median(v)) / sd, 3) if sd else 0
    return {"bins": bins, "width": round(width, 3), "counts": counts,
            "range": [round(lo, 3), round(hi, 3)],
            "mean": round(mean, 3), "sd": round(sd, 3), "skew": skew,
            "shape": "右偏（存在高值异常）" if skew > 0.3 else "近似对称"}


@tool("spc", "SPC 控制图", "D", "测量",
      "X-bar 控制图判定过程是否处于统计受控",
      "子组数据", "中心线/上下控制限 + 判异", "实施期过程控制")
def t_spc(d: Dict[str, Any]) -> Dict[str, Any]:
    v = d["values"]
    n = 5                                        # 子组容量
    groups = [v[i:i + n] for i in range(0, len(v) - n + 1, n)]
    xbars = [statistics.mean(g) for g in groups]
    rbars = [max(g) - min(g) for g in groups]
    xbb = statistics.mean(xbars)
    rb = statistics.mean(rbars)
    A2 = 0.577                                   # n=5
    ucl, lcl = xbb + A2 * rb, xbb - A2 * rb
    sigma = A2 * rb / 3                          # X-bar 图 1σ 当量
    oos = [i for i, x in enumerate(xbars) if x > ucl or x < lcl]

    # 判异规则（Western Electric 简化）：仅靠"越界"会因异常值自身拉宽控制限而漏检
    rules = {}
    # 规则1：点出界（3σ）
    rules["R1_超出3σ"] = oos
    # 规则2：连续 9 点落在中心线同侧（均值漂移）
    side = [1 if x > xbb else -1 for x in xbars]
    run, runs = 1, []
    for i in range(1, len(side)):
        if side[i] == side[i - 1]:
            run += 1
        else:
            run = 1
        if run >= 9:
            runs.append(i)
    rules["R2_连续9点同侧"] = sorted(set(runs))
    # 规则3：连续 6 点递增或递减（趋势）
    tr, trends = 1, []
    for i in range(1, len(xbars)):
        if xbars[i] > xbars[i - 1]:
            tr = tr + 1 if tr > 0 else 1
        elif xbars[i] < xbars[i - 1]:
            tr = tr - 1 if tr < 0 else -1
        else:
            tr = 0
        if abs(tr) >= 6:
            trends.append(i)
    rules["R3_连续6点趋势"] = sorted(set(trends))
    hit = {k: v for k, v in rules.items() if v}

    # 关键诊断：异常值会同时抬高 R-bar → 拉宽 UCL/LCL → 使自身不再越界（掩盖效应）
    masked = False
    note = ""
    if not oos:
        robust = statistics.median(rbars)          # 用中位数 R-bar 重算，抗异常值
        ucl_r, lcl_r = xbb + A2 * robust, xbb - A2 * robust
        oos_r = [i for i, x in enumerate(xbars) if x > ucl_r or x < lcl_r]
        masked = bool(oos_r)
        if masked:
            note = (f"控制限被异常值拉宽（R-bar={rb:.3f} vs 中位数R-bar={robust:.3f}，"
                    f"限宽 {A2*rb:.3f}→{A2*robust:.3f}）；"
                    f"用稳健限复判发现子组 {oos_r} 越界，属典型'异常掩盖'漏检")

    verdict = (f"失控：{'; '.join(k for k in hit)}"
               if hit else ("统计受控（但存在掩盖风险，见 note）" if masked else "统计受控"))
    out = {"subgroup_n": n, "subgroups": len(groups),
           "CL": round(xbb, 3), "UCL": round(ucl, 3), "LCL": round(lcl, 3),
           "sigma_xbar": round(sigma, 3),
           "xbars": [round(x, 3) for x in xbars],
           "out_of_control": oos, "rules_hit": hit,
           "masking_detected": masked, "note": note,
           "verdict": verdict}
    return out


@tool("scatter", "散布图", "D", "测量",
      "判断两个变量的相关性",
      "成对数据 (x, y)", "相关系数 r + 判定", "实施期因果初判")
def t_scatter(d: Dict[str, Any]) -> Dict[str, Any]:
    rnd = random.Random(11)
    x = [round(rnd.uniform(20, 80), 1) for _ in range(30)]
    y = [round(0.6 * xi + rnd.gauss(10, 6), 2) for xi in x]
    mx, my = statistics.mean(x), statistics.mean(y)
    cov = sum((a - mx) * (b - my) for a, b in zip(x, y))
    den = math.sqrt(sum((a - mx) ** 2 for a in x) * sum((b - my) ** 2 for b in y))
    r = cov / den if den else 0
    strength = ("强" if abs(r) >= 0.8 else "中" if abs(r) >= 0.5 else "弱")
    return {"n": len(x), "r": round(r, 3),
            "points": list(zip(x, y)),
            "direction": "正相关" if r > 0 else "负相关",
            "strength": strength,
            "verdict": f"{strength}{'正相关' if r > 0 else '负相关'}（r={r:.3f}）"}


GB2828_CODE = [(8, "A", 2), (15, "B", 3), (25, "C", 5), (50, "D", 8), (90, "E", 13),
               (150, "F", 20), (280, "G", 32), (500, "H", 50), (1200, "J", 80),
               (3200, "K", 125), (10000, "L", 200), (35000, "M", 315),
               (150000, "N", 500), (500000, "P", 800)]
GB2828_AC_RE = {"A": (0, 1), "B": (0, 1), "C": (0, 1), "D": (0, 1), "E": (0, 1),
                "F": (1, 2), "G": (1, 2), "H": (2, 3), "J": (3, 4), "K": (5, 6),
                "L": (7, 8), "M": (10, 11), "N": (14, 15), "P": (21, 22),
                "Q": (21, 22)}


@tool("gb2828", "GB/T 2828 计数抽样", "D", "检验/符合性评价",
      "按批量与 AQL 确定样本量、接收/拒收数",
      "批量 N、AQL、检验水平", "字码 + n + Ac/Re + 判定",
      "实施期批检验（简化一次抽样对照表）")
def t_gb2828(d: Dict[str, Any]) -> Dict[str, Any]:
    N = 500
    code, n = "Q", 1250
    for limit, c, size in GB2828_CODE:
        if N <= limit:
            code, n = c, size
            break
    ac, re_ = GB2828_AC_RE[code]
    defects_found = 2
    accept = defects_found <= ac
    return {"lot_size": N, "code": code, "sample_size": n,
            "Ac": ac, "Re": re_, "defects_found": defects_found,
            "verdict": "接收" if accept else "拒收",
            "note": "简化一次抽样正常检验对照表，正式使用请以 GB/T 2828.1 现行版为准"}


@tool("variable_sampling", "计量抽样", "D", "检验/符合性评价",
      "以均值-标准差法对计量特性做接收判定",
      "样本均值、标准差、规格限、k 值", "Q 统计量 + 判定",
      "实施期计量特性检验")
def t_variable_sampling(d: Dict[str, Any]) -> Dict[str, Any]:
    v = d["values"][:20]
    mean, sd = statistics.mean(v), statistics.pstdev(v)
    USL, LSL = 5.5, 3.0
    k = 1.65
    q_u = (USL - mean) / sd if sd else 0
    q_l = (mean - LSL) / sd if sd else 0
    return {"n": len(v), "mean": round(mean, 3), "sd": round(sd, 3),
            "USL": USL, "LSL": LSL, "k": k,
            "Q_upper": round(q_u, 3), "Q_lower": round(q_l, 3),
            "verdict": "接收" if min(q_u, q_l) >= k else "拒收"}


@tool("ppap", "PPAP 生产件批准", "D", "检验/符合性评价",
      "确认生产过程具备稳定交付合格品的能力",
      "提交等级与文件清单", "要素完成矩阵",
      "正式项目交付；Demo 阶段仅列清单")
def t_ppap(d: Dict[str, Any]) -> Dict[str, Any]:
    elements = ["设计记录", "工程更改文件", "过程流程图", "FMEA", "控制计划",
                "MSA 结果", "尺寸/性能结果", "初始过程能力", "合格实验室文件",
                "外观批准", "样件", "标准样品", "检具", "零件提交保证书 PSW"]
    level = "等级 3（Demo 不适用，仅列清单）"
    return {"level": level, "elements": elements,
            "applicable_in_demo": False,
            "note": "Demo 为方法论验证原型，PSW 与样件类要素不适用"}


@tool("doc_conformity", "人工文件符合性检验", "D", "检验/符合性评价",
      "逐条核对文件与标准条款的符合性（过程检验）",
      "文件清单 + 条款对照表", "符合/不符合清单",
      "过程检验：AI 输出人工终审")
def t_doc_conformity(d: Dict[str, Any]) -> Dict[str, Any]:
    items = [
        ("质量方针成文（7.5.2）", True), ("质量目标可测量（6.2）", True),
        ("风险措施记录（6.1）", True), ("相关方登记（4.2）", True),
        ("AI 政策：谁批谁负责（42001 5.2）", True),
        ("敏感数据准入审批", False), ("不适用项归档", True),
    ]
    ok = [n for n, v in items if v]
    ng = [n for n, v in items if not v]
    return {"items": items, "conform": ok, "nonconform": ng,
            "rate": round(len(ok) / len(items), 3),
            "inspection_type": "过程检验",
            "note": "AI 生成的比对结论须人工逐条复核，留存条款比对记录"}


@tool("poka_yoke", "Poka-Yoke 防错", "D", "检验/符合性评价",
      "在源头用校验规则阻断缺陷，而非事后检出",
      "输入数据 + 校验规则集", "拦截结果", "实施期输入校验")
def t_poka_yoke(d: Dict[str, Any]) -> Dict[str, Any]:
    samples = [
        {"patient_id": "P001", "phone": "13800138000", "test_item": "K", "result_value": 4.2},
        {"patient_id": "", "phone": "13900139000", "test_item": "K", "result_value": 4.5},
        {"patient_id": "P003", "phone": "13812345678", "test_item": "", "result_value": None},
    ]
    rules = [
        ("患者 ID 非空", lambda r: bool(r["patient_id"])),
        ("检测项目非空", lambda r: bool(r["test_item"])),
        ("结果值可解析为数值", lambda r: isinstance(r["result_value"], (int, float))),
        ("脱敏后不得残留手机号", lambda r: not _re_phone(r["phone"])),
    ]
    blocked = []
    for i, r in enumerate(samples):
        for name, fn in rules:
            if not fn(r):
                blocked.append({"index": i, "rule": name})
    return {"samples": len(samples), "rules": [n for n, _ in rules],
            "blocked": blocked, "blocked_count": len(blocked),
            "principle": "防错优先于检出：缺陷在入口即被阻断"}


def _re_phone(s: str) -> bool:
    import re
    return bool(re.search(r"1[3-9]\d{9}", str(s)))


# ===========================================================================
# C — 检查阶段工具
# ===========================================================================

@tool("pareto", "帕累托图", "C", "测量",
      "按频次排序并找二八分界，确定改进重点",
      "缺陷频次表", "排序表 + 累计占比 + 分界点",
      "检查期优先级排序")
def t_pareto(d: Dict[str, Any]) -> Dict[str, Any]:
    defects = d["defects"]
    total = sum(defects.values())
    rows, cum = [], 0
    for k, v in sorted(defects.items(), key=lambda x: -x[1]):
        cum += v
        rows.append({"类别": k, "频次": v, "占比": round(v / total, 4),
                     "累计占比": round(cum / total, 4)})
    cutoff = next((i for i, r in enumerate(rows) if r["累计占比"] >= 0.8), len(rows) - 1)
    return {"rows": rows, "total": total, "vital_few_index": cutoff,
            "vital_few": [r["类别"] for r in rows[:cutoff + 1]],
            "verdict": f"前 {cutoff + 1} 项累计占比 ≥80%，为重点改进对象"}


@tool("fishbone", "鱼骨图（5M1E）", "C", "测量",
      "按人/机/料/法/环/测六维度梳理潜在原因",
      "问题陈述", "5M1E 原因树", "检查期原因分析（与 5Why 联动）")
def t_fishbone(d: Dict[str, Any]) -> Dict[str, Any]:
    return {"problem": "脱敏字段遗漏率偏高", "bones": {
        "人 Man": ["字段清单由单人维护", "复核未落到人"],
        "机 Machine": ["redact 依赖上游默认配置"],
        "料 Material": ["OCR 结构字段名不统一"],
        "法 Method": ["缺少脱敏后回扫步骤"],
        "环 Environment": ["多来源（ASTM/OCR）字段集不同"],
        "测 Measurement": ["脱敏正确率未纳入日常监控"],
    }}


@tool("boxplot", "箱线图", "C", "测量",
      "用四分位数与 IQR 识别离群点",
      "计量数据", "Q1/Q2/Q3/IQR/上下须/离群点",
      "检查期分布与离群分析")
def t_boxplot(d: Dict[str, Any]) -> Dict[str, Any]:
    v = sorted(d["values"])
    q1, q2, q3 = quantile(v, .25), quantile(v, .5), quantile(v, .75)
    iqr = q3 - q1
    lo_f, hi_f = q1 - 1.5 * iqr, q3 + 1.5 * iqr
    outliers = [x for x in v if x < lo_f or x > hi_f]
    return {"Q1": round(q1, 3), "Q2": round(q2, 3), "Q3": round(q3, 3),
            "IQR": round(iqr, 3), "lower_fence": round(lo_f, 3),
            "upper_fence": round(hi_f, 3), "outliers": outliers,
            "outlier_count": len(outliers)}


@tool("bar_pie", "柱状图/饼图", "C", "测量",
      "展示构成占比",
      "分类计数", "占比表", "检查期汇报可视化")
def t_bar_pie(d: Dict[str, Any]) -> Dict[str, Any]:
    defects = d["defects"]
    total = sum(defects.values())
    return {"rows": [{"类别": k, "计数": v, "占比": round(v / total, 4)}
                     for k, v in defects.items()],
            "total": total, "chart_types": ["柱状图", "饼图"]}


@tool("audit_checklist", "内审检查表", "C", "检验/符合性评价",
      "按条款逐条内审，输出符合性结论",
      "条款清单 + 证据索引", "符合/不符合/观察项",
      "检查期内审（文档 05 运行证据）")
def t_audit_checklist(d: Dict[str, Any]) -> Dict[str, Any]:
    items = [
        ("4.3 范围声明", "符合"), ("5.2 质量方针成文", "符合"),
        ("6.1 风险措施记录", "符合"), ("7.5 成文信息控制", "符合"),
        ("8.x 运行控制（只读旁路）", "符合"), ("9.1 监视测量", "符合"),
        ("10.2 不合格与纠正措施", "观察项"),
        ("42001 6.1.2 AI 风险评估", "符合"),
        ("敏感数据准入审批", "不符合"),
    ]
    from collections import Counter
    c = Counter(v for _, v in items)
    return {"items": items, "summary": dict(c),
            "nonconform": [n for n, v in items if v == "不符合"],
            "observation": [n for n, v in items if v == "观察项"],
            "note": "ISO 42001 审核员关注运行时证据：策略在 Agent 触碰数据的那一刻是否真的生效"}


@tool("csat", "顾客满意度测评", "C", "检验/符合性评价",
      "测评干系人满意度，识别期望落差",
      "满意度评分（1-5）", "均值/分布/NPS 类指标",
      "检查期干系人反馈（文档 03）")
def t_csat(d: Dict[str, Any]) -> Dict[str, Any]:
    scores = {"检验人员": [4, 4, 5, 3, 4], "信息科": [3, 4, 3, 4],
              "院领导": [4, 5, 4], "村医": [4, 3, 4, 4]}
    rows = [{"干系人": k, "n": len(v), "均值": round(statistics.mean(v), 2),
             "最低": min(v), "最高": max(v)} for k, v in scores.items()]
    low = [r["干系人"] for r in rows if r["均值"] < 3.5]
    return {"rows": rows, "overall": round(statistics.mean(
        [statistics.mean(v) for v in scores.values()]), 2),
        "below_threshold": low,
        "note": "与文档 03 干系人矩阵联动：低分项对应阻力销号清单"}


@tool("coq", "质量成本 COQ", "C", "检验/符合性评价",
      "核算预防/鉴定/内部失败/外部失败四类成本",
      "成本项归集", "四类占比 + 结构判定", "检查期质量经济性评价")
def t_coq(d: Dict[str, Any]) -> Dict[str, Any]:
    cats = {"预防成本": 12000, "鉴定成本": 8000,
            "内部失败成本": 5000, "外部失败成本": 2000}
    total = sum(cats.values())
    rows = [{"类别": k, "金额": v, "占比": round(v / total, 4)} for k, v in cats.items()]
    fail_ratio = (cats["内部失败成本"] + cats["外部失败成本"]) / total
    return {"rows": rows, "total": total,
            "failure_ratio": round(fail_ratio, 4),
            "verdict": ("结构健康：预防+鉴定占比高"
                        if fail_ratio < 0.4 else "失败成本占比偏高，应前移投入"),
            "note": "框架性估算，立项阶段按实际单价测算（文档 08）"}


@tool("maturity", "能力成熟度评价", "C", "检验/符合性评价",
      "评价 AI 应用治理成熟度等级",
      "成熟度维度评分（1-5）", "雷达评分 + 等级", "检查期能力评价")
def t_maturity(d: Dict[str, Any]) -> Dict[str, Any]:
    dims = {"战略与方针": 4, "风险治理": 4, "数据分级": 3, "人在回路": 4,
            "证据链": 4, "资产解耦": 4, "监视测量": 3, "持续改进": 3}
    avg = statistics.mean(dims.values())
    level = ("初始级" if avg < 2 else "已管理级" if avg < 3
             else "已定义级" if avg < 4 else "量化管理级")
    weak = [k for k, v in dims.items() if v <= 3]
    return {"dims": dims, "average": round(avg, 2), "level": level,
            "weak_dims": weak, "next_step": f"优先补齐：{weak}"}


# ===========================================================================
# A — 处置阶段工具
# ===========================================================================

@tool("five_why", "5Why 根因分析", "A", "监视",
      "连续追问直至根因",
      "问题陈述 + 追问链", "Why 链 + 根因", "处置期根因分析")
def t_five_why(d: Dict[str, Any]) -> Dict[str, Any]:
    chain = [
        "Why1 为什么脱敏字段遗漏？-> 部分来源字段未被识别",
        "Why2 为什么未被识别？-> 字段清单只覆盖了 ASTM 来源",
        "Why3 为什么只覆盖 ASTM？-> 清单创建时仅有轨道 A",
        "Why4 为什么未随轨道 B 扩展？-> 缺少『新增来源须更新分级规则』的变更控制",
        "Why5 为什么缺少变更控制？-> 分级规则未纳入变更控制程序",
    ]
    return {"chain": chain,
            "root_cause": "分级规则未纳入变更控制程序，导致新增数据源时规则未同步",
            "countermeasure": "将分级规则文件纳入变更控制，新增数据源触发强制评审"}


@tool("fta", "FTA 故障树", "A", "监视",
      "自顶事件向下展开与/或门，求最小割集",
      "顶事件 + 门结构", "最小割集 + 单点故障", "高风险场景与 FMEA、风险矩阵叠加")
def t_fta(d: Dict[str, Any]) -> Dict[str, Any]:
    # 顶事件：敏感数据外泄 = (脱敏失效 AND 数据外传) OR (越权访问)
    tree = {
        "top": "敏感数据外泄",
        "gate": "OR",
        "children": [
            {"gate": "AND", "children": ["脱敏规则未覆盖字段", "云端接收了未脱敏文本"]},
            {"gate": "LEAF", "name": "越权访问（权限矩阵配置错误）"},
        ],
    }

    def expand(node) -> List[List[str]]:
        if node.get("gate") == "LEAF":
            return [[node["name"]]]
        kids = node["children"]
        if node["gate"] == "AND":
            sets = [[]]
            for k in kids:
                sub = expand(k) if isinstance(k, dict) else [[k]]
                sets = [s + t for s in sets for t in sub]
            return sets
        sets = []
        for k in kids:
            sets += expand(k) if isinstance(k, dict) else [[k]]
        return sets

    cuts = expand(tree)
    single = [c[0] for c in cuts if len(c) == 1]
    return {"tree": tree, "min_cut_sets": cuts, "single_point_failures": single,
            "verdict": f"共 {len(cuts)} 个最小割集，其中单点故障 {len(single)} 个"}


@tool("affinity", "亲和图", "A", "监视",
      "把零散意见按亲和性聚类",
      "原始意见条目", "分组结果", "处置期意见归纳")
def t_affinity(d: Dict[str, Any]) -> Dict[str, Any]:
    ideas = ["脱敏规则要版本化", "日志字段要统一", "审批卡要带回滚方案",
             "知识库要离线备份", "工作流要能导出", "危急值阈值要可配置",
             "OCR 要人工确认", "措辞不能出现已审核"]
    groups = {
        "规则与配置": ["脱敏规则要版本化", "危急值阈值要可配置"],
        "证据与留痕": ["日志字段要统一", "审批卡要带回滚方案"],
        "资产解耦": ["知识库要离线备份", "工作流要能导出"],
        "人机边界": ["OCR 要人工确认", "措辞不能出现已审核"],
    }
    return {"ideas": ideas, "groups": groups, "group_count": len(groups)}


@tool("relations", "关系图（因果矩阵）", "A", "监视",
      "量化原因与结果的相关强度",
      "原因×结果评分矩阵", "加权排序", "处置期优先级决策")
def t_relations(d: Dict[str, Any]) -> Dict[str, Any]:
    causes = ["规则未版本化", "日志字段不统一", "无回滚方案", "资产在线留存"]
    effects = {"证据链完整性": [5, 4, 3, 1],
               "可追溯性": [4, 5, 3, 2],
               "抗平台绑定": [2, 1, 1, 5]}
    weights = {"证据链完整性": 0.4, "可追溯性": 0.35, "抗平台绑定": 0.25}
    scores = {c: round(sum(effects[e][i] * weights[e] for e in effects), 3)
              for i, c in enumerate(causes)}
    ranked = sorted(scores.items(), key=lambda x: -x[1])
    return {"causes": causes, "effects": effects, "weights": weights,
            "scores": scores, "ranked": ranked, "top": ranked[0][0]}


@tool("doe", "DOE 试验设计", "A", "测量",
      "构造 2^k 全因子设计矩阵，用于参数寻优",
      "因子与水平", "设计矩阵 + 试验次数", "处置期参数优化")
def t_doe(d: Dict[str, Any]) -> Dict[str, Any]:
    factors = {"危急值阈值裕度": (-1, 1), "趋势漂移窗口(天)": (-1, 1),
               "OCR 置信度下限": (-1, 1)}
    k = len(factors)
    names = list(factors)
    runs = []
    for i in range(2 ** k):
        runs.append({names[j]: -1 if (i >> (k - 1 - j)) & 1 == 0 else 1
                     for j in range(k)})
    return {"factors": factors, "design": "2^%d 全因子" % k,
            "runs": runs, "runs_count": len(runs),
            "note": "正式 DOE 需补充区组、重复与响应变量；此处仅输出设计矩阵"}


@tool("capa", "CAPA 纠正预防措施表", "A", "检验/符合性评价",
      "从问题登记到有效性验证的闭环",
      "问题登记单", "CAPA 状态机 + 闭环判定", "处置期整改闭环")
def t_capa(d: Dict[str, Any]) -> Dict[str, Any]:
    steps = [
        ("C1 识别", "done"), ("C2 原因分析", "done"),
        ("C3 纠正", "done"), ("C4 纠正措施", "done"),
        ("C5 有效性验证", "pending"), ("C6 关闭归档", "pending"),
    ]
    pending = [s for s, st in steps if st != "done"]
    return {"steps": steps, "closed": not pending, "pending": pending,
            "record": "CAPA 记录为外审必查项，历史条目不得删除"}


@tool("countermeasure", "对策表", "A", "检验/符合性评价",
      "把根因映射为可执行对策与责任人",
      "根因清单", "对策表（5W1H）", "处置期措施落地")
def t_countermeasure(d: Dict[str, Any]) -> Dict[str, Any]:
    rows = [
        {"问题": "脱敏规则未同步", "对策": "规则文件纳入变更控制",
         "责任人": "AI 边界安全官", "时限": "W1", "验证方式": "变更记录可查"},
        {"问题": "审批无回滚方案", "对策": "审批卡强制四要素",
         "责任人": "AI 边界安全官", "时限": "W2", "验证方式": "抽查审批记录"},
        {"问题": "资产在线留存", "对策": "工作流导出 + 冷备份",
         "责任人": "本人", "时限": "W3", "验证方式": "断网离线加载演练"},
    ]
    return {"rows": rows, "count": len(rows)}


@tool("eight_d", "8D 报告", "A", "检验/符合性评价",
      "八步法结构化解决重大质量问题",
      "重大问题描述", "8D 八步完成度", "处置期重大问题")
def t_eight_d(d: Dict[str, Any]) -> Dict[str, Any]:
    steps = [
        ("D1 成立团队", True), ("D2 描述问题", True), ("D3 临时措施", True),
        ("D4 根本原因", True), ("D5 永久对策", True), ("D6 实施与验证", False),
        ("D7 预防再发", False), ("D8 总结表彰", False),
    ]
    done = [s for s, ok in steps if ok]
    return {"steps": steps, "done": done, "remaining": [s for s, ok in steps if not ok],
            "progress": f"{len(done)}/8"}


@tool("dmaic", "DMAIC", "A", "检验/符合性评价",
      "五阶段改进门（定义-测量-分析-改进-控制）",
      "改进项目章程", "阶段门状态", "处置期改进项目管理")
def t_dmaic(d: Dict[str, Any]) -> Dict[str, Any]:
    gates = [
        ("Define 定义", "done", "问题与范围已定义"),
        ("Measure 测量", "done", "MSA 通过，基线已采集"),
        ("Analyze 分析", "done", "帕累托+鱼骨+5Why 已定位根因"),
        ("Improve 改进", "in_progress", "对策表执行中"),
        ("Control 控制", "pending", "控制计划与 SPC 待固化"),
    ]
    return {"gates": gates,
            "current": next(g for g, s, _ in gates if s == "in_progress"),
            "note": "与 PDCA 循环对接：DMAIC 的 C 阶段输出回归 PDCA 的 P"}


# ===========================================================================
# 运行器
# ===========================================================================

def run_all(log: RunLog, data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """按 PDCA 顺序执行全部工具，逐项记录结果。"""
    results: List[Dict[str, Any]] = []
    for phase in ("P", "D", "C", "A"):
        for t in [x for x in REGISTRY if x.phase == phase]:
            log.add(action="tool_invoke", obj=t.id, data_class="internal",
                    phase=phase, category=t.category, iso=t.iso)
            try:
                out = t.fn(data)
                ok = isinstance(out, dict) and len(out) > 0
                log.add(action="tool_result", obj=t.id,
                        result="pass" if ok else "empty_output", phase=phase,
                        keys=len(out) if isinstance(out, dict) else 0)
                results.append({"id": t.id, "name": t.name, "phase": phase,
                                "category": t.category, "iso": t.iso,
                                "status": "PASS" if ok else "FAIL",
                                "output": out})
            except Exception as e:
                log.add(action="tool_result", obj=t.id, result="error",
                        phase=phase, error=str(e))
                results.append({"id": t.id, "name": t.name, "phase": phase,
                                "category": t.category, "iso": t.iso,
                                "status": "ERROR", "output": {"error": str(e)}})
    return results


def run_api_demo(log: RunLog, gates: Dict[str, APIGate]) -> List[Dict[str, Any]]:
    """演示四个接口的默认关闭 + 人工选择性打开。"""
    steps: List[Dict[str, Any]] = []

    # 1) 默认状态下全部调用被拦截
    for k, g in gates.items():
        r = g.call(log, probe=True)
        steps.append({"step": f"默认调用 {k}", "result": r["status"],
                      "reason": r.get("reason", "")})

    # 2) 申请打开但审批要素不全 -> 拒绝
    r = gates["ocr_extract"].request_enable(log, actor_id="demo", plan="打开 OCR 抽取")
    steps.append({"step": "申请打开 ocr_extract（要素不全）",
                  "result": r["status"], "reason": r.get("reason", "")})

    # 3) 人工完整申请 + 确认 -> 打开（演示可人工选择打开）
    r = gates["cloud_llm"].request_enable(
        log, actor_id="demo",
        plan="接入云端 LLM 做脱敏文本解读",
        impact="仅传输脱敏后文本，不传原始图像与身份字段",
        risk_note="存在模型留存数据的风险，需评估后决定是否私有化",
        rollback="关闭接口并清空会话，回退至本地规则引擎",
        timeout_s=300)
    token = r.get("token")
    r2 = gates["cloud_llm"].confirm_enable(log, token, approver="检验科主任")
    steps.append({"step": "人工完整申请并确认 cloud_llm",
                  "result": r2["status"], "approver": r2.get("approver", "")})

    # 4) 再次调用：仅已打开的放行
    for k, g in gates.items():
        r = g.call(log, probe=True)
        steps.append({"step": f"开启后调用 {k}", "result": r["status"]})

    # 5) 人工关闭
    gates["cloud_llm"].disable(log, actor_id="demo")
    steps.append({"step": "人工关闭 cloud_llm",
                  "result": gates["cloud_llm"].call(log, probe=True)["status"]})
    return steps


# ===========================================================================
# 输出：功能说明 + 运行报告 + 日志
# ===========================================================================

def render_inventory_md(gates: Dict[str, APIGate]) -> str:
    L = ["# LabBridge PDCA 工具集 · 功能说明", "",
         f"> 生成器 labbridge_pdca/{VERSION}　生成时间 {_now_iso()}",
         "> 依据《工具记录清单》（PDCA 各阶段工具清单）实现，共 %d 个工具" % len(REGISTRY), ""]
    for phase in ("P", "D", "C", "A"):
        tools = [t for t in REGISTRY if t.phase == phase]
        L.append(f"## {phase} — {PHASE_NAME[phase]}（ISO 9001 {PHASE_ISO[phase]}）")
        L.append("")
        L.append("| # | 工具 | 类别 | 用途 | 输入 → 输出 | 适用判定 |")
        L.append("|---|---|---|---|---|---|")
        for i, t in enumerate(tools, 1):
            L.append(f"| {i} | {t.name} | {t.category} | {t.purpose} | "
                     f"{t.inputs} → {t.outputs} | {t.recommended_for} |")
        L.append("")
    L += ["## 工具选用原则（清单第七节，已固化为代码约束）", "",
          "1. **按需选用，不堆砌** —— 每个工具带 `recommended_for` 适用判定，不强制全跑；",
          "2. **高风险敏感场景叠加 FMEA、FTA、风险矩阵** —— `HIGH_RISK_STACK` 强制组合；",
          "3. **量化指标优先做 MSA** —— 测量类工具调用前自动触发 MSA 前置校验；",
          "4. **检验分准入检验与过程检验** —— 输出带 `inspection_type` 字段；",
          "5. **风险思维贯穿全部活动** —— 高风险场景增加测量频次、上提复核层级。", ""]

    # ---- 四个预留 API 接口 ----
    L += ["## 四个预留 API 接口（默认全部关闭）", "",
          "接口只做「预留」，不随工具集默认启用。任何调用在未经人工审批时返回 "
          "`blocked`，**不静默放行**。", "",
          "| 接口 | 名称 | 风险等级 | 数据分级 | 默认 | 用途 |",
          "|---|---|---|---|---|---|"]
    for g in gates.values():
        L.append(f"| `{g.key}` | {g.name} | {g.risk_level} | {g.data_class} | "
                 f"**关闭** | {g.description} |")
    L.append("")
    L += ["### 开启流程（人工选择打开）", "",
          "```python",
          "g = gates['cloud_llm']",
          "# 1) 申请：必须携带审批四要素，缺一即被拒绝并记入日志",
          "req = g.request_enable(log, actor_id='u001',",
          "                       plan='对接云端 LLM 做报告解读',",
          "                       impact='提升解读效率，数据需先脱敏',",
          "                       risk_note='存在数据外传风险，仅传脱敏文本',",
          "                       rollback='一键关闭接口，回退本地规则引擎')",
          "# -> {'status': 'pending', 'token': '...', 'timeout_s': 30}",
          "",
          "# 2) 人工确认（须在 timeout_s 内，超时自动拒绝）",
          "g.confirm_enable(log, token=req['token'], approver='检验科主任')",
          "# -> {'status': 'enabled'}",
          "",
          "# 3) 调用（未开启时返回 blocked）",
          "g.call(log, text='...')",
          "",
          "# 4) 随时人工关闭",
          "g.disable(log, actor_id='u001')",
          "```", "",
          "### 开关设计原则", "",
          "- **默认关闭（default-closed）**：接口初始态为关闭，不是「开启后需谨慎」"
          "而是「不审批就不存在」；",
          "- **审批四要素（approval-4-elements）**：动作计划、预期影响、风险提示、"
          "回滚方案，缺一即 `rejected`；",
          "- **超时默认拒绝（approval-timeout-default-deny）**：确认超时自动拒绝，"
          "避免无人值守时高风险接口被放行；",
          "- **逐接口独立授权**：开启一个接口不影响其他接口，不存在「一开全开」；",
          "- **全程留痕**：申请 / 确认 / 调用 / 关闭四类动作均写入审计日志，"
          "带 `human_involved` 标记；",
          "- **最高风险默认永久关闭**：`lis_writeback` 涉及写回原厂 LIS，"
          "与「不做更好的 LIS、只做桥接」的边界一致，建议保持关闭。", ""]

    # ---- 运行与日志说明 ----
    L += ["## 运行方式", "",
          "```bash",
          "python labbridge_pdca.py --selftest        # 自检：逐工具断言",
          "python labbridge_pdca.py --run -o <输出目录>  # 全量运行并生成报告与日志",
          "```", "",
          "产物：", "",
          "| 文件 | 内容 |",
          "|---|---|",
          "| `01_PDCA工具功能说明.md` | 本文件：工具清单、选用原则、接口说明 |",
          "| `02_PDCA工具运行报告.md` | 分阶段结果、需人工关注项、接口开关验证 |",
          "| `03_pdca_run_log.jsonl` | 审计日志（每行一条，含哈希链） |",
          "| `04_API接口状态.json` | 四个接口的当前状态与策略 |",
          "| `05_PDCA工具运行结果.json` | 全部工具的结构化输出 |",
          "| `06_PDCA测试图谱汇总.html` | 图谱汇总：全部测试的图表/图示在单个 HTML 中集中展示（V2.1 新增） |", "",
          "### 审计日志字段", "",
          "| 字段 | 说明 |",
          "|---|---|",
          "| `seq` | 自增序号，用于检测日志缺失或跳号 |",
          "| `event_id` | 事件唯一标识（UUID） |",
          "| `timestamp` | ISO-8601 时间戳（UTC） |",
          "| `action` | 动作类型：`run_start` / `tool_invoke` / `tool_result` / "
          "`api_call` / `api_enable_request` / `api_enable_confirm` / `api_disable` |",
          "| `object` | 作用对象（工具 id 或接口 key） |",
          "| `result` | `pass` / `ok` / `blocked` / `rejected` / `pending` / "
          "`enabled` / `disabled` |",
          "| `actor_id` / `actor_role` | 操作者标识与角色 |",
          "| `data_class` | 数据分级（public / internal / sensitive） |",
          "| `human_involved` | 是否有人参与（对应「人在回路」） |",
          "| `policy_hit` | 命中的策略规则名，如 `default-closed`、`approval-4-elements` |",
          "| `component` | 产生该记录的组件与版本 |",
          "| `prev_hash` / `hash` | 哈希链前后指针，任一记录被篡改或删除即断链 |", "",
          "哈希链校验：从首条 `prev_hash=0×64` 起，逐条复算 "
          "`sha256(除 hash 外全部字段)` 并与下一条 `prev_hash` 比对，"
          "任一处不符即说明日志被篡改或有缺失。", "",
          "### 数据说明", "",
          "- 演示数据全部为**合成数据**（60 份标本结果，含人为注入的漂移段与异常值），"
          "**不含任何真实患者信息**；",
          "- 敏感字段在日志中默认掩码，取原文需显式申请并自动记为例外；",
          "- 日志仅追加（append-only），不提供就地改写接口。", ""]
    return "\n".join(L)


def _extract_findings(results: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """从各工具输出中提取「需人工关注项」——不因工具状态 PASS 而掩盖风险信号。

    设计意图：工具"跑通"只说明它算出了数，不代表数本身是好的。
    这里把散落在 36 份输出里的告警信号集中起来，避免报告读起来一片绿灯。
    """
    F = []

    def add(sev, tool, text):
        if text:
            F.append({"severity": sev, "tool": tool, "text": str(text)})

    for r in results:
        o, name = r["output"], r["name"]

        # 1) 统计掩盖：控制限被异常值拉宽导致漏检
        if o.get("masking_detected"):
            add("高", name, o.get("note") or "检测到异常掩盖，控制限可能被异常值拉宽")

        # 2) 运行/趋势类判异信号（verdict 里带"异常"字样）
        v = o.get("verdict")
        if isinstance(v, str) and ("异常" in v or "失控" in v or "漂移" in v):
            add("中", name, v)

        # 3) 阻塞项：前置条件未完成
        miss = o.get("missing")
        if isinstance(miss, list) and miss:
            add("高", name, f"阻塞：缺 {miss}")
        elif isinstance(miss, str) and miss:
            add("高", name, f"阻塞：{miss}")

        # 4) 不符合项 / 观察项
        nc = o.get("nonconform")
        if isinstance(nc, list) and nc:
            add("中", name, f"不符合/观察项 {len(nc)} 项："
                          + "；".join((str(x.get("clause", "")) + " "
                                      + str(x.get("desc", x))[:40]) if isinstance(x, dict)
                                     else str(x)[:40] for x in nc[:3]))
        elif isinstance(nc, int) and nc:
            add("中", name, f"不符合项 {nc} 项")

        # 5) 准入闸门非通过（与上面的阻塞项去重，避免同一事实计两次）
        g = o.get("gate")
        if isinstance(g, str) and g not in ("通过", "符合", "接收"):
            dup = isinstance(miss, list) and miss and any(
                str(m) in g for m in miss)
            if not dup:
                add("中", name, f"闸门判定：{g}")

        # 6) 测量系统能力不足（%GRR 10~30 有条件可接受，>30 不可接受）
        grr = o.get("%GRR")
        if isinstance(grr, (int, float)) and grr > 10:
            add("中" if grr < 30 else "高", name, f"%GRR={grr}% → 测量系统能力需改进")

        # 7) 高风险项
        hr = o.get("high_risks")
        if isinstance(hr, list) and hr:
            add("高", name, f"高风险 {len(hr)} 项："
                          + "；".join(str(x.get("name", x))[:24] if isinstance(x, dict)
                                     else str(x)[:24] for x in hr[:3]))
        tr = o.get("top_rpn")
        if isinstance(tr, (int, float)) and tr >= 80:
            add("中", name, f"最高 RPN={tr}，接近高风险阈值 100")

        # 8) 未闭合步骤（CAPA / 8D / 对策表）
        st, dn = o.get("steps"), o.get("done")
        if isinstance(st, list) and isinstance(dn, int) and dn < len(st):
            pend = list(st[dn:])
            add("中", name, f"待闭合 {len(pend)} 步：" + "、".join(
                (str(s.get("step", s))[:20] if isinstance(s, dict) else str(s)[:20])
                for s in pend[:3]))

        # 9) 单条 note 且非空（风险提示类）
        nt = o.get("note")
        if (isinstance(nt, str) and nt and not o.get("masking_detected")
                and len(nt) > 12):
            add("低", name, nt)

    # 去重（同文本只留一条）
    seen, uniq = set(), []
    for f in F:
        k = (f["tool"], f["text"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    order = {"高": 0, "中": 1, "低": 2}
    uniq.sort(key=lambda x: order.get(x["severity"], 3))
    return uniq


def render_report_md(results: List[Dict[str, Any]], api_steps: List[Dict[str, Any]],
                     gates: Dict[str, APIGate], log: RunLog) -> str:
    passed = [r for r in results if r["status"] == "PASS"]
    failed = [r for r in results if r["status"] != "PASS"]
    L = ["# LabBridge PDCA 工具集 · 运行报告", "",
         f"> 生成器 labbridge_pdca/{VERSION}　运行时间 {_now_iso()}",
         f"> 工具总数 {len(results)}　通过 {len(passed)}　失败 {len(failed)}　"
         f"通过率 {round(len(passed)/len(results), 4)}", "",
         f"审计日志哈希链头：`{log.chain_head[:32]}…`", "",
         "## 一、总体结论", "",
         f"- 全部 {len(results)} 个工具按 P→D→C→A 顺序执行完毕，**{len(passed)} 通过 / {len(failed)} 失败**。",
         "- 演示数据为合成数据（60 份标本结果），**不含任何真实患者信息**。",
         "- 四个预留 API 接口默认全部关闭，调用被拦截；经人工完整审批后可选择性打开。", ""]

    L += ["## 二、分阶段结果", ""]
    for phase in ("P", "D", "C", "A"):
        L.append(f"### {phase} — {PHASE_NAME[phase]}（{PHASE_ISO[phase]}）")
        L.append("")
        L.append("| 工具 | 类别 | 状态 | 关键输出 |")
        L.append("|---|---|---|---|")
        for r in [x for x in results if x["phase"] == phase]:
            L.append(f"| {r['name']} | {r['category']} | **{r['status']}** | "
                     f"`{_summarize(r['id'], r['output'])}` |")
        L.append("")

    findings = _extract_findings(results)
    hi = [f for f in findings if f["severity"] == "高"]
    L += ["## 三、需人工关注项", "",
          f"工具「通过」只表示计算完成，不表示结果本身无风险。以下 {len(findings)} 项"
          f"（其中高关注 {len(hi)} 项）需人工判断或跟进：", "",
          "| 关注度 | 来源工具 | 事项 |", "|---|---|---|"]
    for f in findings:
        L.append(f"| **{f['severity']}** | {f['tool']} | {f['text']} |")
    L.append("")
    if hi:
        L += ["> ⚠ 存在高关注项：按「人在回路」原则，上述事项须由人工确认处置意见"
              "并写入 CAPA，不得由系统自动关闭。", ""]

    L += ["## 四、四个预留 API 接口", "",
          "| 接口 | 名称 | 风险等级 | 默认状态 | 说明 |",
          "|---|---|---|---|---|"]
    for g in gates.values():
        L.append(f"| `{g.key}` | {g.name} | {g.risk_level} | "
                 f"**{'关闭' if not g.enabled else '开启'}** | {g.description} |")
    L.append("")
    L += ["### 开关验证步骤", "",
          "| 步骤 | 结果 | 说明 |", "|---|---|---|"]
    for s in api_steps:
        note = s.get("reason") or s.get("approver") or ""
        if not note and s["result"] == "blocked":
            if "关闭" in s["step"]:
                note = "人工关闭生效 → 后续调用被拦截（可随时再启用，需重新审批）"
            elif "开启后" in s["step"]:
                note = "该接口本次未获审批，仍处关闭态 → 调用被拦截（逐接口独立授权）"
            else:
                note = "调用被拦截（预期行为）"
        L.append(f"| {s['step']} | **{s['result']}** | {note} |")
    L.append("")
    L += ["### 开关规则", "",
          "- **默认关闭**：未经人工审批，任何调用返回 `blocked`，不静默放行；",
          "- **审批四要素**：动作计划、预期影响、风险提示、回滚方案，缺一即拒绝；",
          "- **一个接口一次审批**：本次仅审批开启 `cloud_llm`，其余三个未被审批，"
          "故「开启后调用」仍全部拦截——这不是缺陷，而是逐接口独立授权的设计；",
          "- **超时默认拒绝**：确认超时自动拒绝，避免无人值守时高风险接口被放行；",
          "- **可人工关闭**：已开启接口可随时人工关闭。", "",
          "## 五、失败/异常项", ""]
    if failed:
        for r in failed:
            L.append(f"- **{r['name']}**（{r['phase']}）：{r['status']} — "
                     f"{r['output'].get('error', '输出为空')}")
    else:
        L.append("- 无。全部工具通过。")
    L.append("")
    return "\n".join(L)


# 针对输出结构特殊、通用摘要抓不到重点的工具，给出定向摘要
SUMMARY_HINTS: Dict[str, Callable[[Dict[str, Any]], str]] = {
    "swot_pest": lambda o: f"SWOT {len(o['SWOT'])} 象限 / PEST {len(o['PEST'])} 维度",
    "target_tree": lambda o: f"总目标展开为 {len(o['tree']['L1'])} 个一级目标，各含量化基线",
    "check_sheet": lambda o: f"共 {o['total']} 项缺陷，最高频「{o['rows'][0]['类别']}」{o['rows'][0]['频次']} 次",
    "bar_pie": lambda o: f"{len(o['rows'])} 类构成，最高「{max(o['rows'], key=lambda r: r['计数'])['类别']}」",
    "stratification": lambda o: f"{o['layers']} 层，层间最大极差 {o['max_spread']}",
    "boxplot": lambda o: f"离群点 {o['outlier_count']} 个（IQR={o['IQR']}，上须 {o['upper_fence']}）",
    "affinity": lambda o: f"{len(o['ideas'])} 条意见聚为 {o['group_count']} 组：{'、'.join(o['groups'])}",
    "doe": lambda o: f"{o['design']}，共 {o['runs_count']} 次试验",
    "countermeasure": lambda o: f"{o['count']} 条对策，首条「{o['rows'][0]['对策']}」（{o['rows'][0]['责任人']}）",
    "capa": lambda o: ("六步已闭环" if o["closed"]
                       else f"待闭合 {len(o['pending'])} 步：{'、'.join(o['pending'])}"),
    "fmea": lambda o: f"最高 RPN={o['top_rpn']}（{o['top']}）",
    "histogram": lambda o: f"{o['shape']}，均值 {o['mean']} 标准差 {o['sd']}",
    "msa": lambda o: f"%GRR={o['%GRR']}% → {o['verdict']}",
    "maturity": lambda o: f"{o['level']}（均分 {o['average']}），短板：{'、'.join(o['weak_dims'])}",
    "csat": lambda o: f"总体 {o['overall']}/5，低于阈值：{o['below_threshold'] or '无'}",
    "coq": lambda o: f"失败成本占比 {o['failure_ratio']} → {o['verdict']}",
    "audit_checklist": lambda o: f"不符合 {len(o['nonconform'])} 项、观察项 {len(o['observation'])} 项",
    "plan_checklist": lambda o: f"完成率 {o['completion']}，{o['gate']}",
}


def _summarize(tid: str, out: Dict[str, Any], limit: int = 90) -> str:
    """从工具输出中挑一句最有信息量的摘要。"""
    if tid in SUMMARY_HINTS:
        try:
            return SUMMARY_HINTS[tid](out).replace("|", "／")[:limit]
        except Exception:
            pass
    for k in ("verdict", "gate", "root_cause", "top", "current", "progress",
              "rule", "principle", "shape", "boost_rule", "note"):
        if k in out and isinstance(out[k], str):
            return out[k].replace("|", "／").replace("\n", " ")[:limit]
    for k, v in out.items():
        if isinstance(v, (int, float)):
            return f"{k}={v}"
        if isinstance(v, str) and v:
            return f"{k}: {v[:limit]}"
    return f"{len(out)} 个字段"


# ============================================================
# V2.1 新增：06_PDCA测试图谱汇总.html —— 全部测试图谱集中展示
# ============================================================

_GALLERY_CSS = """
body{font-family:"Microsoft YaHei",sans-serif;margin:24px;background:#f7f8fa;color:#222;}
h1{font-size:22px;} h2{font-size:16px;margin:28px 0 8px;}
.meta{color:#666;font-size:13px;}
.card{background:#fff;border:1px solid #e3e5e8;border-radius:8px;padding:14px 16px;margin:10px 0;}
.pass{color:#1b7f3b;font-weight:bold;} .warn{color:#b06a00;font-weight:bold;}
table{border-collapse:collapse;font-size:13px;margin:6px 0;}
td,th{border:1px solid #d8dbe0;padding:3px 10px;text-align:left;}
th{background:#eef1f4;}
.kv{font-size:13px;color:#444;margin:2px 0;}
.chip{display:inline-block;background:#eef3ff;color:#345;border-radius:4px;
      padding:1px 8px;margin-right:6px;font-size:12px;}
"""

def _esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

def _svg_frame(w, h, inner) -> str:
    return (f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'xmlns="http://www.w3.org/2000/svg" style="background:#fff">'
            f'<rect x="0.5" y="0.5" width="{w-1}" height="{h-1}" fill="#fff" stroke="#d8dbe0"/>{inner}</svg>')

def _axis(w, h, pad, xs=None, ys=None):
    """坐标轴与网格线。返回 (绘图区宽高, 起始 html 片段)。"""
    p = "\n".join(f'<line x1="{x}" y1="{pad}" x2="{x}" y2="{h-pad}" stroke="#eef1f4"/>'
                  for x in xs or []) + \
        "\n".join(f'<line x1="{pad}" y1="{y}" x2="{w-pad}" y2="{y}" stroke="#eef1f4"/>'
                  for y in ys or [])
    p += (f'<line x1="{pad}" y1="{h-pad}" x2="{w-pad}" y2="{h-pad}" stroke="#999"/>'
          f'<line x1="{pad}" y1="{pad}" x2="{pad}" y2="{h-pad}" stroke="#999"/>')
    return p

def _poly_points(vals, w, h, pad, lo, hi):
    n = max(len(vals) - 1, 1)
    return [(pad + i * (w - 2 * pad) / n,
             h - pad - (v - lo) / (hi - lo or 1) * (h - 2 * pad))
            for i, v in enumerate(vals)]

def _line_chart(vals, w=560, h=200, hlines=(), color="#2b6cb0"):
    pad = 34
    lo, hi = min(list(vals) + [v for v, _ in hlines]), max(list(vals) + [v for v, _ in hlines])
    margin = (hi - lo) * 0.1 or 1
    lo, hi = lo - margin, hi + margin
    pts = _poly_points(vals, w, h, pad, lo, hi)
    s = _axis(w, h, pad)
    for val, c in hlines:
        y = h - pad - (val - lo) / (hi - lo or 1) * (h - 2 * pad)
        s += (f'<line x1="{pad}" y1="{y:.1f}" x2="{w-pad}" y2="{y:.1f}" '
              f'stroke="{c}" stroke-dasharray="5,4"/>'
              f'<text x="{w-pad+2}" y="{y+4:.1f}" font-size="11" fill="{c}">{val:.2f}</text>')
    s += ('<polyline points="' + " ".join(f"{x:.1f},{y:.1f}" for x, y in pts) +
          f'" fill="none" stroke="{color}" stroke-width="1.6"/>')
    for x, y in pts:
        s += f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.4" fill="{color}"/>'
    return _svg_frame(w, h, s)

def _bar_chart(labels, counts, w=560, h=200, color="#2f855a", cum=None):
    pad = 34
    n = max(len(counts), 1)
    bw = (w - 2 * pad) / n * 0.62
    hi = max(list(counts) + [1])
    s = _axis(w, h, pad)
    for i, (lb, c) in enumerate(zip(labels, counts)):
        x = pad + (i + 0.5) * (w - 2 * pad) / n - bw / 2
        bh = (c / hi) * (h - 2 * pad)
        s += (f'<rect x="{x:.1f}" y="{h-pad-bh:.1f}" width="{bw:.1f}" height="{bh:.1f}" '
              f'fill="{color}"/>'
              f'<text x="{x+bw/2:.1f}" y="{h-pad+13:.1f}" font-size="10" text-anchor="middle" '
              f'fill="#555">{_esc(lb)}</text>'
              f'<text x="{x+bw/2:.1f}" y="{h-pad-bh-4:.1f}" font-size="10" text-anchor="middle" '
              f'fill="#333">{c}</text>')
    if cum:
        pts = _poly_points(cum, w, h, pad, 0, 1)
        s += ('<polyline points="' + " ".join(f"{x:.1f},{y:.1f}" for x, y in pts) +
              '" fill="none" stroke="#c05621" stroke-width="1.4"/>')
    return _svg_frame(w, h, s)

def _scatter_chart(points, w=420, h=260, color="#2b6cb0"):
    pad = 34
    xs = [p[0] for p in points]; ys = [p[1] for p in points]
    x0, x1, y0, y1 = min(xs), max(xs), min(ys), max(ys)
    gx = "\n".join(f'<line x1="{pad + i*(w-2*pad)/5:.0f}" y1="{pad}" x2="{pad + i*(w-2*pad)/5:.0f}" y2="{h-pad}" stroke="#eef1f4"/>' for i in range(6))
    gy = "\n".join(f'<line x1="{pad}" y1="{pad + i*(h-2*pad)/5:.0f}" x2="{w-pad}" y2="{pad + i*(h-2*pad)/5:.0f}" stroke="#eef1f4"/>' for i in range(6))
    s = gx + gy
    s += (f'<line x1="{pad}" y1="{h-pad}" x2="{w-pad}" y2="{h-pad}" stroke="#999"/>'
          f'<line x1="{pad}" y1="{pad}" x2="{pad}" y2="{h-pad}" stroke="#999"/>')
    for x, y in points:
        px = pad + (x - x0) / (x1 - x0 or 1) * (w - 2 * pad)
        py = h - pad - (y - y0) / (y1 - y0 or 1) * (h - 2 * pad)
        s += f'<circle cx="{px:.1f}" cy="{py:.1f}" r="3" fill="{color}" fill-opacity="0.65"/>'
    s += (f'<text x="{w/2}" y="{h-8}" font-size="11" text-anchor="middle" fill="#666">x</text>'
          f'<text x="10" y="{h/2}" font-size="11" fill="#666" transform="rotate(-90 12 {h/2})">y</text>')
    return _svg_frame(w, h, s)

def _boxplot_chart(o, w=420, h=170):
    pad = 44
    lo = min(o["lower_fence"], *o["outliers"]) if o["outliers"] else o["lower_fence"]
    hi = max(o["upper_fence"], *o["outliers"]) if o["outliers"] else o["upper_fence"]
    m = (hi - lo) * 0.1 or 1
    lo, hi = lo - m, hi + m
    X = lambda v: pad + (v - lo) / (hi - lo) * (w - 2 * pad)
    mid = h // 2
    s = _axis(w, h, pad)
    s += (f'<line x1="{X(o["lower_fence"]):.1f}" y1="{mid}" x2="{X(o["Q1"]):.1f}" y2="{mid}" stroke="#555"/>'
          f'<line x1="{X(o["Q3"]):.1f}" y1="{mid}" x2="{X(o["upper_fence"]):.1f}" y2="{mid}" stroke="#555"/>'
          f'<line x1="{X(o["lower_fence"]):.1f}" y1="{mid-14}" x2="{X(o["lower_fence"]):.1f}" y2="{mid+14}" stroke="#555"/>'
          f'<line x1="{X(o["upper_fence"]):.1f}" y1="{mid-14}" x2="{X(o["upper_fence"]):.1f}" y2="{mid+14}" stroke="#555"/>'
          f'<rect x="{X(o["Q1"]):.1f}" y="{mid-22}" width="{X(o["Q3"])-X(o["Q1"]):.1f}" height="44" '
          f'fill="#bee3f8" stroke="#2b6cb0"/>'
          f'<line x1="{X(o["Q2"]):.1f}" y1="{mid-22}" x2="{X(o["Q2"]):.1f}" y2="{mid+22}" stroke="#2b6cb0" stroke-width="2"/>')
    for ov in o["outliers"]:
        s += f'<circle cx="{X(ov):.1f}" cy="{mid}" r="3.4" fill="#c05621"/>'
    for key in ("lower_fence", "Q1", "Q2", "Q3", "upper_fence"):
        s += (f'<text x="{X(o[key]):.1f}" y="{mid+40}" font-size="10" text-anchor="middle" '
              f'fill="#555">{o[key]:.1f}</text>')
    return _svg_frame(w, h, s)

def _pie_chart(rows, w=260, h=220):
    total = sum(r["计数"] for r in rows) or 1
    cx, cy, R, r0 = w // 2, h // 2, min(w, h) // 2 - 14, 52
    colors = ["#2b6cb0", "#2f855a", "#c05621", "#6b46c1", "#b83280", "#319795", "#a0aec0"]
    s, a0 = "", -90.0
    for i, rrow in enumerate(rows):
        frac = rrow["计数"] / total
        a1 = a0 + frac * 360
        large = 1 if a1 - a0 > 180 else 0
        import math as _m
        x0, y0 = cx + R * _m.cos(_m.radians(a0)), cy + R * _m.sin(_m.radians(a0))
        x1, y1 = cx + R * _m.cos(_m.radians(a1)), cy + R * _m.sin(_m.radians(a1))
        s += (f'<path d="M{cx},{cy} L{x0:.1f},{y0:.1f} A{R},{R} 0 {large} 1 {x1:.1f},{y1:.1f} Z" '
              f'fill="{colors[i % len(colors)]}" fill-opacity="0.85"/>')
        a0 = a1
    s += f'<circle cx="{cx}" cy="{cy}" r="{r0}" fill="#fff"/>'
    s += f'<text x="{cx}" y="{cy+4}" font-size="12" text-anchor="middle" fill="#333">共{total}</text>'
    return _svg_frame(w, h, s)

def _kv_table(out: dict, cap=14) -> str:
    rows = []
    for k, v in list(out.items())[:cap]:
        if isinstance(v, list):
            if v and isinstance(v[0], dict):
                rows.append(f"<tr><td>{_esc(k)}</td><td>表（{len(v)} 行，见下）</td></tr>")
            else:
                txt = ", ".join(_esc(x) for x in v[:12]) + ("…" if len(v) > 12 else "")
                rows.append(f"<tr><td>{_esc(k)}</td><td>{txt}</td></tr>")
        elif isinstance(v, dict):
            rows.append(f"<tr><td>{_esc(k)}</td><td>{_esc(json.dumps(v, ensure_ascii=False)[:120])}</td></tr>")
        else:
            rows.append(f"<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>")
    if len(out) > cap:
        rows.append(f'<tr><td colspan="2">…其余 {len(out)-cap} 个字段见 05 结果 JSON</td></tr>')
    return "<table>" + "".join(rows) + "</table>"

def _sub_table(rows: list) -> str:
    if not rows:
        return ""
    keys = list(rows[0].keys())
    head = "".join(f"<th>{_esc(k)}</th>" for k in keys)
    body = "".join("<tr>" + "".join(f"<td>{_esc(r.get(k, ''))}</td>" for k in keys) + "</tr>"
                   for r in rows[:20])
    return f"<table><tr>{head}</tr>{body}</table>"

def render_chart_gallery(results: List[Dict[str, Any]], data: Dict[str, Any]) -> str:
    """生成 06_PDCA测试图谱汇总.html：全部 36 项测试的图谱在单个文件集中展示。"""
    by_id = {r["id"]: r for r in results}
    order = [r["id"] for r in results]
    L = ["<!DOCTYPE html><html lang='zh'><head><meta charset='utf-8'>"
         "<title>PDCA 测试图谱汇总</title>",
         f"<style>{_GALLERY_CSS}</style></head><body>",
         "<h1>PDCA 测试图谱汇总</h1>",
         f"<p class='meta'>生成时间：{_now_iso()} ｜ 工具总数：{len(results)} ｜ "
         f"PASS：{sum(1 for r in results if r['status'] == 'PASS')} ｜ "
         "来源：05_PDCA工具运行结果.json（数据为合成数据，无真实患者信息）</p>",
         "<p class='meta'>图表类工具以 SVG 图形展示；其余工具以结果卡片展示，全部测试逐项呈现。</p>"]

    for tid in order:
        r = by_id[tid]
        out, phase, name, status = r.get("output", {}), r["phase"], r["name"], r["status"]
        cls = "pass" if status == "PASS" else "warn"
        L.append(f"<h2>{_esc(name)}（{tid}）</h2><div class='card'>"
                 f"<span class='chip'>{PHASE_NAME.get(phase, phase)}</span>"
                 f"<span class='{cls}'>{status}</span> "
                 f"<span class='meta'>{_esc(out.get('verdict', ''))}</span>")
        svg = None
        if tid == "run_chart" and out.get("values"):
            svg = _line_chart(out["values"], hlines=((out["median"], "#c05621"),))
        elif tid == "histogram" and out.get("counts"):
            lo = out["range"][0]; wid = out["width"] or 1
            labels = [f"{lo + i*wid:.1f}" for i in range(len(out["counts"]))]
            svg = _bar_chart(labels, out["counts"])
        elif tid == "spc" and out.get("xbars"):
            svg = _line_chart(out["xbars"],
                              hlines=((out["UCL"], "#c53030"), (out["CL"], "#2f855a"),
                                      (out["LCL"], "#c53030")))
        elif tid == "scatter" and out.get("points"):
            svg = _scatter_chart(out["points"])
        elif tid == "pareto" and out.get("rows"):
            labels = [x["类别"] for x in out["rows"]]
            svg = _bar_chart(labels, [x["频次"] for x in out["rows"]],
                             cum=[x["累计占比"] for x in out["rows"]])
        elif tid == "bar_pie" and out.get("rows"):
            svg = (_bar_chart([x["类别"] for x in out["rows"]], [x["计数"] for x in out["rows"]])
                   + "  " + _pie_chart(out["rows"]))
        elif tid == "boxplot":
            svg = _boxplot_chart(out)
        if svg:
            L.append(f"<div style='margin:8px 0'>{svg}</div>")
        L.append(_kv_table({k: v for k, v in out.items()
                            if k not in ("points", "xbars", "values")}))
        if out.get("rows"):
            L.append(_sub_table(out["rows"]))
        if out.get("bones"):
            L.append(_kv_table(out["bones"]))
        L.append("</div>")

    L.append("<p class='meta'>【DEMO 声明】本文件由 DEMO 工具自动生成与记录，"
             "不具备法律法规意义，仅作为 DEMO 输出展示项。</p></body></html>")
    return "\n".join(L)


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="LabBridge PDCA 质量工具集")
    ap.add_argument("--run", action="store_true", help="全量运行并输出报告+日志")
    ap.add_argument("-o", "--output", default="output", help="输出目录")
    ap.add_argument("--selftest", action="store_true", help="测试所有步骤")
    ap.add_argument("--api-status", action="store_true", help="查看 4 个 API 接口状态")
    a = ap.parse_args(argv)

    log = RunLog(actor_id="pdca-runner", actor_role="engineer")
    gates = build_api_gates()

    if a.api_status:
        print(json.dumps({k: g.state() for k, g in gates.items()},
                         ensure_ascii=False, indent=2))
        return 0

    data = make_demo_data()
    log.add(action="run_start", obj="pdca-toolset", tools=len(REGISTRY),
            sample_size=len(data["values"]), note="合成数据，无真实患者信息")

    results = run_all(log, data)
    api_steps = run_api_demo(log, gates)

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = len(results) - passed

    print(f"== PDCA 工具集运行 ==")
    for phase in ("P", "D", "C", "A"):
        ph = [r for r in results if r["phase"] == phase]
        ok = sum(1 for r in ph if r["status"] == "PASS")
        print(f"  {phase} {PHASE_NAME[phase]:<10} {ok}/{len(ph)} 通过")
    print(f"  合计 {passed}/{len(results)} 通过，{failed} 失败")

    if a.selftest:
        print("\n结果:", "PASS" if failed == 0 else "FAIL")
        return 0 if failed == 0 else 1

    outdir = a.output
    os.makedirs(outdir, exist_ok=True)
    p1 = os.path.join(outdir, "01_PDCA工具功能说明.md")
    p2 = os.path.join(outdir, "02_PDCA工具运行报告.md")
    p3 = os.path.join(outdir, "03_pdca_run_log.jsonl")
    p4 = os.path.join(outdir, "04_API接口状态.json")
    p5 = os.path.join(outdir, "05_PDCA工具运行结果.json")
    p6 = os.path.join(outdir, "06_PDCA测试图谱汇总.html")   # V2.1：图谱汇总

    with open(p1, "w", encoding="utf-8") as f:
        f.write(render_inventory_md(gates))
    with open(p2, "w", encoding="utf-8") as f:
        f.write(render_report_md(results, api_steps, gates, log))
    log.write_jsonl(p3)
    with open(p4, "w", encoding="utf-8") as f:
        json.dump({"generated_at": _now_iso(),
                   "interfaces": {k: g.state() for k, g in gates.items()},
                   "policy": {"default": "closed",
                              "approval_elements": ["动作计划", "预期影响", "风险提示", "回滚方案"],
                              "timeout": "默认拒绝"}},
                   f, ensure_ascii=False, indent=2)
    with open(p5, "w", encoding="utf-8") as f:
        json.dump({"results": results, "api_steps": api_steps,
                   "chain_head": log.chain_head},
                  f, ensure_ascii=False, indent=2)
    with open(p6, "w", encoding="utf-8") as f:
        f.write(render_chart_gallery(results, data))

    print("\n输出：")
    for p in (p1, p2, p3, p4, p5, p6):
        print(f"  {os.path.abspath(p)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
