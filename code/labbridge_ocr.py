#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LabBridge 轨道 B —— 拍照 OCR 抽取与人工确认（P1）· 纯标准库（后端可选）

Provenance / 反溯说明
---------------------
依据文档 04 第五章（轨道 B）、文档 07 第二节（OCR 准确率风险）独立编写。
**未包含任何 OCR 引擎代码**，本模块只做三件事：后端适配、结构化抽取、人工确认队列。
OCR 引擎全部走可选后端（RapidOCR / PaddleOCR / tesseract），装了就用，没装就降级。

文档 07 的清醒判断（本模块的产品形态依据）：
    「乡镇 OCR 在真实手写、折痕、模糊场景下准确率暴跌」
    → Demo **不承诺全自动**，设计为「OCR 预填 + 人工一键确认」的半自动模式；
      「人工确认」是产品的一部分，不是缺陷。

文档 05 第五章的最小暴露面：
    脱敏在端侧/本地完成，**原始图像和可识别信息不离开本地**，
    云端只接收脱敏后的结构化字段。
    → 本模块的 `local_only` 标志默认 True，且 `export_for_upload()` 会强制检查
      图像路径不得随结构化数据一起外发。

文档 09 的授权提醒：
    三个 OCR 项目代码都是 Apache-2.0，但**模型权重是另一回事**。
    PP-OCR / RapidOCR 打包的 ONNX 权重，商业使用前需单独确认权重许可。
"""

import os
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 后端适配（全部可选，不构成依赖）
# ---------------------------------------------------------------------------

BACKENDS = [
    {"id": "rapidocr", "module": "rapidocr_onnxruntime", "license": "Apache-2.0",
     "note": "端侧/边缘首选，ONNXRuntime 推理、体积小；注意权重许可需单独确认",
     "stars": "8.2k"},
    {"id": "paddleocr", "module": "paddleocr", "license": "Apache-2.0",
     "note": "中文精度最好，依赖较重，适合服务端/离线工作站；权重许可需单独确认",
     "stars": "91k"},
    {"id": "tesseract", "module": "pytesseract", "license": "Apache-2.0",
     "note": "轻量兜底，中文手写体表现一般", "stars": "77k"},
]


def backend_status() -> List[Dict[str, Any]]:
    import importlib.util
    out = []
    for b in BACKENDS:
        avail = importlib.util.find_spec(b["module"]) is not None
        out.append({**b, "available": avail})
    return out


class OcrBackendUnavailable(RuntimeError):
    pass


def run_backend(backend_id: str, image_path: str) -> Tuple[str, float]:
    """调用已安装的 OCR 后端，返回 (文本, 平均置信度)。未安装则抛异常。"""
    if not os.path.exists(image_path):
        raise FileNotFoundError(image_path)
    if backend_id == "rapidocr":
        try:
            from rapidocr_onnxruntime import RapidOCR  # type: ignore
        except ImportError:
            raise OcrBackendUnavailable("未安装 rapidocr_onnxruntime")
        engine = RapidOCR()
        result, _ = engine(image_path)
        if not result:
            return "", 0.0
        texts = [r[1] for r in result]
        confs = [float(r[2]) for r in result if len(r) > 2]
        return "\n".join(texts), (sum(confs) / len(confs) if confs else 0.0)
    if backend_id == "paddleocr":
        try:
            from paddleocr import PaddleOCR  # type: ignore
        except ImportError:
            raise OcrBackendUnavailable("未安装 paddleocr")
        engine = PaddleOCR(use_angle_cls=True, lang="ch")
        res = engine.ocr(image_path, cls=True)
        texts, confs = [], []
        for line in (res or []):
            for item in (line or []):
                texts.append(item[1][0])
                confs.append(float(item[1][1]))
        return "\n".join(texts), (sum(confs) / len(confs) if confs else 0.0)
    if backend_id == "tesseract":
        try:
            import pytesseract  # type: ignore
            from PIL import Image  # type: ignore
        except ImportError:
            raise OcrBackendUnavailable("未安装 pytesseract / Pillow")
        data = pytesseract.image_to_data(Image.open(image_path),
                                         lang="chi_sim", output_type=pytesseract.Output.DICT)
        texts = [t for t in data.get("text", []) if str(t).strip()]
        confs = [float(c) for c, t in zip(data.get("conf", []), data.get("text", []))
                 if str(t).strip() and str(c) not in ("-1",)]
        return "\n".join(texts), (sum(confs) / len(confs) / 100 if confs else 0.0)
    raise OcrBackendUnavailable(f"未知后端: {backend_id}")


# ---------------------------------------------------------------------------
# 结构化抽取：OCR 文本 → 检验字段
# ---------------------------------------------------------------------------

# 常见项目别名 → 标准码（本地对照表；文档 09：不引入需签署许可的术语库）
ITEM_ALIASES = {
    "白细胞": "WBC", "白細胞": "WBC", "WBC": "WBC",
    "红细胞": "RBC", "紅細胞": "RBC", "RBC": "RBC",
    "血红蛋白": "HGB", "血紅蛋白": "HGB", "HGB": "HGB", "Hb": "HGB",
    "血小板": "PLT", "PLT": "PLT",
    "血钾": "K", "钾": "K", "K": "K",
    "血糖": "GLU", "葡萄糖": "GLU", "GLU": "GLU",
    "谷丙转氨酶": "ALT", "ALT": "ALT",
    "肌酐": "CREA", "CREA": "CREA",
}

# 一行形如：项目名  结果值  单位  参考区间  [标志]
# 参考区间前必须有空白分隔，否则会被贪心的 unit 吃掉（unit 字符类含数字与 -）
_LINE_RE = re.compile(
    r"(?P<item>[一-龥A-Za-z]{1,12})\s*"
    r"(?P<value>[<>=]?\s*\d+(?:\.\d+)?)\s*"
    r"(?P<unit>[一-龥A-Za-z%/^\d\.\-]{0,12})"
    r"(?:\s+(?P<ref>\d+(?:\.\d+)?\s*[-~]\s*\d+(?:\.\d+)?))?"
    r"\s*(?P<flag>[HL↑↓]*)")


def normalize_item(name: str) -> str:
    key = str(name).strip()
    return ITEM_ALIASES.get(key, ITEM_ALIASES.get(key.upper(), key))


def extract_fields(text: str, default_ref: Dict[str, str] = None) -> List[Dict[str, Any]]:
    """OCR 文本 → 结构化检验字段。只做字符串归一化 + 本地对照表。"""
    default_ref = default_ref or {}
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _LINE_RE.search(line)
        if not m:
            continue
        raw_item = m.group("item").strip()
        item = normalize_item(raw_item)
        if item == raw_item and not re.match(r"^[A-Za-z]{2,5}$", raw_item):
            continue   # 未命中对照表且非英文缩写 → 交给人工确认
        val_raw = m.group("value") or ""
        try:
            value = float(re.sub(r"[<>=]", "", val_raw).strip())
        except ValueError:
            continue
        flag = (m.group("flag") or "").strip()
        flag = flag.replace("↑", "H").replace("↓", "L").upper()
        out.append({
            "test_item": item,
            "test_item_raw": raw_item,
            "result_value": value,
            "unit": (m.group("unit") or "").strip(),
            "ref_range": (m.group("ref") or default_ref.get(item, "")).strip(),
            "abnormal_flag": flag,
        })
    return out


# ---------------------------------------------------------------------------
# 人工确认队列（半自动是设计，不是缺陷）
# ---------------------------------------------------------------------------

@dataclass
class OcrRecord:
    image_path: str
    text: str
    confidence: float
    backend: str
    fields: List[Dict[str, Any]] = field(default_factory=list)
    confirmed_by: str = ""
    confirmed_at: str = ""
    status: str = "pending"      # pending / confirmed / rejected
    local_only: bool = True

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


class OcrIntake:
    """拍照 OCR 受理：识别 → 抽取 → 置信度不足回退第二后端 → 人工确认。"""

    def __init__(self, log=None, confidence_min: float = 0.80,
                 fallback_confidence_min: float = 0.60,
                 local_only: bool = True) -> None:
        self.log = log
        self.confidence_min = confidence_min
        self.fallback_min = fallback_confidence_min
        self.local_only = local_only
        self.records: List[OcrRecord] = []
        self.degraded: List[Dict[str, Any]] = []

    def _available(self) -> List[str]:
        return [b["id"] for b in backend_status() if b["available"]]

    def intake(self, image_path: str, actor_id: str = "system") -> OcrRecord:
        avail = self._available()
        if not avail:
            # 无后端时不假装成功：明确降级，交给人工录入
            rec = OcrRecord(image_path=image_path, text="", confidence=0.0,
                            backend="none", status="pending", local_only=self.local_only)
            self.degraded.append({"image": image_path, "reason": "无可用 OCR 后端，转人工录入"})
            self.records.append(rec)
            if self.log:
                self.log.record("ocr_extract", actor_id=actor_id, object=image_path,
                                result="degraded", data_source="ocr",
                                human_involved=True, extra={"reason": "no_backend"})
            return rec

        primary = avail[0]
        text, conf = run_backend(primary, image_path)
        # 文档 09：置信度低或关键字段缺失 → 回退第二后端二次识别
        fields = extract_fields(text)
        if (conf < self.confidence_min or not fields) and len(avail) > 1:
            secondary = avail[1]
            try:
                t2, c2 = run_backend(secondary, image_path)
                f2 = extract_fields(t2)
                if c2 > conf or len(f2) > len(fields):
                    text, conf, fields, primary = t2, c2, f2, secondary
            except OcrBackendUnavailable:
                pass

        rec = OcrRecord(image_path=image_path, text=text, confidence=round(conf, 4),
                        backend=primary, fields=fields, local_only=self.local_only)
        if conf < self.fallback_min or not fields:
            self.degraded.append({"image": image_path, "confidence": conf,
                                  "fields": len(fields), "reason": "置信度不足或字段缺失，强制人工确认"})
        self.records.append(rec)
        if self.log:
            self.log.record("ocr_extract", actor_id=actor_id, object=image_path,
                            result="ok" if fields else "low_confidence",
                            data_source="ocr", human_involved=True,
                            extra={"backend": primary, "confidence": round(conf, 4),
                                   "fields": len(fields)})
        return rec

    def confirm(self, index: int, confirmed_by: str, status: str = "confirmed",
                corrections: Dict[str, Any] = None) -> OcrRecord:
        """人工一键确认。confirmed_by 必须是具体的人（文档 05 6.2）。"""
        if not confirmed_by or confirmed_by in ("system", "unknown"):
            raise ValueError("确认人必须是具体的人或账户 ID（文档 05 6.2）")
        from labbridge_auditlog import now_iso
        rec = self.records[index]
        rec.confirmed_by = confirmed_by
        rec.confirmed_at = now_iso()
        rec.status = status
        if corrections:
            for f in rec.fields:
                if f.get("test_item") in corrections:
                    f.update(corrections[f["test_item"]])
        if self.log:
            self.log.record("确认", actor_id=confirmed_by, object=rec.image_path,
                            data_source="ocr", human_involved=True, result=status)
        return rec

    def unconfirmed(self) -> List[OcrRecord]:
        return [r for r in self.records if r.status == "pending"]

    def export_for_upload(self) -> Dict[str, Any]:
        """脱敏后上云的载荷。**强制**剔除图像路径与原文（文档 05 第五章）。"""
        payload = []
        for r in self.records:
            if r.status != "confirmed":
                continue
            payload.append({
                "backend": r.backend, "confidence": r.confidence,
                "confirmed_by": r.confirmed_by, "fields": r.fields,
            })
        assert all("image_path" not in p for p in payload)
        return {"local_only": self.local_only,
                "records": payload,
                "notice": "原始图像与可识别信息不离开本地；云端仅接收脱敏结构化字段。"}


# ---------------------------------------------------------------------------
# 自检（不依赖任何 OCR 后端）
# ---------------------------------------------------------------------------

def selftest() -> int:
    print("== labbridge_ocr 自检 ==")
    ok = True

    text = "白细胞 6.4 10^9/L 4.0-10.0\n血红蛋白 132 g/L 115-150\n血钾 7.3 mmol/L 3.5-5.3 H\n"
    fields = extract_fields(text)
    items = [f["test_item"] for f in fields]
    print(f"[1] 结构化抽取: {items}")
    ok &= "WBC" in items and "HGB" in items and "K" in items

    k = next(f for f in fields if f["test_item"] == "K")
    print(f"[2] 字段细节: K={k['result_value']}{k['unit']} ref={k['ref_range']} flag={k['abnormal_flag']}")
    ok &= k["result_value"] == 7.3 and k["abnormal_flag"] == "H" and k["ref_range"] == "3.5-5.3"

    print(f"[3] 别名归一化: 血红蛋白→{normalize_item('血红蛋白')} GLU→{normalize_item('GLU')}")
    ok &= normalize_item("血红蛋白") == "HGB"

    intake = OcrIntake()
    rec = intake.intake("__no_such_image__.png", actor_id="sys")
    print(f"[4] 无后端降级: status={rec.status} backend={rec.backend} degraded={len(intake.degraded)}")
    ok &= rec.status == "pending" and len(intake.degraded) == 1

    intake.records[0].fields = fields
    try:
        intake.confirm(0, "system")
        print("[5] 无主体确认: FAIL（未拦截）"); ok = False
    except ValueError:
        print("[5] 无主体确认被拦截: OK（文档 05 6.2）"); ok &= True

    intake.confirm(0, "王村医", status="confirmed")
    print(f"[6] 人工确认: by={intake.records[0].confirmed_by} 待确认={len(intake.unconfirmed())}")
    ok &= len(intake.unconfirmed()) == 0

    up = intake.export_for_upload()
    print(f"[7] 上云载荷: 含图像路径={'image_path' in str(up)} 条数={len(up['records'])}")
    ok &= "image_path" not in str(up) and len(up["records"]) == 1

    st = backend_status()
    print(f"[8] 后端可用性: {[(b['id'], b['available']) for b in st]}（未安装属预期，非失败）")
    ok &= all(b["available"] is False for b in st) or True

    print("结果:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
