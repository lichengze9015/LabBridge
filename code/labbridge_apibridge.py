#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LabBridge API 对接桥 —— 把 4 个预留接口从「开关」变成可真正对接的「端子」

Provenance / 反溯说明
---------------------
自研。本模块不实现任何新协议，只做编排：复用 labbridge_astm（ASTM 只读接收）、
labbridge_deid（脱敏）、labbridge_screen（审核规则）、labbridge_auditlog（哈希链审计）、
labbridge_ocr（OCR 受理，引擎可选）。全部纯标准库，零新增第三方依赖。

四个接口的真实对接形态
----------------------
1. astm_ingest   仪器 ASTM E1381/E1394 接入：
                 simulate（合成会话演示）/ replay（回放抓包文件）/ tcp（TCP 监听，
                 仪器作为 client 连入）/ serial（串口，需 pyserial，未装则明确报错）。
                 接收结果一律经过 脱敏 → 三条审核规则 → 熔断检测 全链路，
                 产出 GUI 记录（检验结果 / 待发列表）与审计日志。
2. ocr_extract   图片目录批量受理：OCR 后端未安装时如实降级为「人工录入队列」，
                 不伪装识别成功。
3. lis_writeback 仅做端点连通性测试（TCP 握手）；**回写本身默认禁止**
                 （文档 04/07：只读旁路，禁止向 LIS/仪器下发数据）。
4. cloud_llm     OpenAI 兼容接口连通性测试。测试请求只发 "ping" 一个 token，
                 **不携带任何患者数据**——真实调用只允许作用于脱敏后的文本。

诚实边界
--------
本模块验证的是「链路与配置是否正确」；连通性测试 PASS 不等于业务联调完成，
接入真实仪器/LIS/云端前仍须按文档 11 第六章逐项确认（字符集、P/O 记录位、
危急值签署等）。

用法:
    python labbridge_apibridge.py --selftest
"""

import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from labbridge_astm import AstmReceiver as ASTMReceiver, simulate_session
from labbridge_auditlog import AuditLog
from labbridge_config import Config
from labbridge_deid import Deidentifier
from labbridge_ocr import OcrIntake, backend_status
from labbridge_screen import ScreenEngine

VERSION = "1.0.0"

DEFAULT_CONFIG: Dict[str, Dict[str, Any]] = {
    "astm_ingest": {
        "mode": "simulate",          # simulate / replay / tcp / serial
        "codec": "UTF-8",            # 国内仪器多发 GBK
        "file_path": "",             # replay 模式：抓包/导出的 .astm/.txt 文件
        "tcp_host": "0.0.0.0",
        "tcp_port": 11000,
        "serial_port": "COM1",
        "serial_baud": 9600,
        "n_samples": 5,              # simulate 模式：合成标本数
        "timeout": 15.0,             # 接收超时（秒）
        "max_records": 200,          # 单次灌入 GUI 记录库的上限
    },
    "ocr_extract": {
        "dir": "",                   # 待扫描图片目录
        "confidence_min": 0.80,
    },
    "lis_writeback": {
        "host": "192.168.1.100",
        "port": 5150,
        "timeout": 5.0,
    },
    "cloud_llm": {
        "base_url": "https://api.openai.com/v1",
        "api_key": "",
        "model": "gpt-4o-mini",
        "timeout": 10.0,
    },
}


def merge_config(stored: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """存储的配置与默认值合并（缺项补默认，多余项保留）。"""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if isinstance(stored, dict):
        for k, v in stored.items():
            if k in cfg and isinstance(v, dict):
                cfg[k].update(v)
    return cfg


# ---------------------------------------------------------------------------
# 1) ASTM 接入：接收 → 脱敏 → 审核规则 → GUI 记录
# ---------------------------------------------------------------------------

def astm_run(cfg: Dict[str, Any], actor_id: str, role: str,
             records_sink: Callable[[List[Dict[str, Any]]], int],
             audit_path: Optional[str] = None,
             receiver: Optional[ASTMReceiver] = None) -> Dict[str, Any]:
    """按配置执行一次 ASTM 接收并灌入全链路。

    records_sink: GUI 提供的落库回调，入参为统一记录列表，返回实际接收条数。
    receiver:     TCP 长监听场景由 GUI 持有实例以便 stop()；其余模式内部自建。
    """
    mode = cfg.get("mode", "simulate")
    codec = cfg.get("codec", "UTF-8")
    os.environ["LABBRIDGE_ASTM_CODEC"] = codec  # labbridge_astm 按调用时读取
    log = AuditLog(audit_path) if audit_path else None

    own = receiver is None
    rcv = receiver or ASTMReceiver(mode=("tcp" if mode == "tcp" else mode),
                                   log=log, receive_timeout=float(cfg.get("timeout", 15.0)))

    t0 = time.time()
    if mode == "simulate":
        raw = simulate_session(n_samples=int(cfg.get("n_samples", 5)))
        rcv.feed_bytes(raw)
        summary = {"mode": "simulate", "frames_ok": rcv.frames_ok,
                   "frames_bad": rcv.frames_bad, "records": len(rcv.records)}
    elif mode == "replay":
        path = cfg.get("file_path") or ""
        if not path or not os.path.isfile(path):
            return {"ok": False, "error": f"回放文件不存在: {path}"}
        summary = rcv.run_replay(path)
    elif mode == "tcp":
        summary = rcv.run_tcp(host=cfg.get("tcp_host", "0.0.0.0"),
                              port=int(cfg.get("tcp_port", 11000)),
                              max_sessions=int(cfg.get("tcp_max_sessions", 1)),
                              timeout=float(cfg.get("timeout", 15.0)))
    elif mode == "serial":
        summary = rcv.run_serial(port=cfg.get("serial_port", "COM1"),
                                 baud=int(cfg.get("serial_baud", 9600)),
                                 timeout=float(cfg.get("timeout", 15.0)))
    else:
        return {"ok": False, "error": f"未知模式: {mode}"}

    # 接收结果 → 统一模型 → 脱敏 → 审核规则（与 NHANES 回放同一链路）
    results = rcv.results()
    for r in results:
        r.setdefault("dept", "检验科")
        r.setdefault("region", "本院")
        r["data_source"] = f"astm_{mode}"
    if not results:
        summary.update({"ok": len(rcv.records) == 0, "ingested": 0,
                        "note": "未收到含结果的数据帧" if rcv.frames_ok else "未收到有效帧",
                        "elapsed_sec": round(time.time() - t0, 2)})
        return summary

    cf = Config()
    de = Deidentifier(config=cf, log=log)
    deid = de.deidentify(results, actor_id=actor_id, role=role,
                         data_source=f"astm_{mode}")
    sc = ScreenEngine(config=cf, log=log)
    screened = sc.screen(deid["records"], actor_id=actor_id, data_source=f"astm_{mode}")

    # → GUI 记录（截断保护，防止一次大灌入撑爆记录库）
    cap = int(cfg.get("max_records", 200))
    gui_records: List[Dict[str, Any]] = []
    watch_items = {id(w.get("result")): w for w in screened["watchlist"]}
    for r in deid["records"][:cap]:
        flag = r.get("abnormal_flag") or ""
        try:
            body = f"{r.get('test_name') or r.get('test_item')} " \
                   f"{r.get('result_value')}{r.get('unit', '')}"
            if flag:
                body += f"（{flag}）"
        except Exception:
            body = str(r)[:80]
        gui_records.append({"type": "检验结果", "content":
                            f"{body}｜伪ID {r.get('patient_pseudo_id', '-')}"
                            f"｜来源 ASTM/{mode}"})
    for w in screened["watchlist"][:cap]:
        # V2.5：显式携带 severity，GUI 台账据此标红，不再依赖文案里的关键词
        gui_records.append({"type": "待发列表",
                            "severity": w.get("severity", ""),
                            "content":
                            f"待关注（{w.get('severity')}）{w.get('test_item')} "
                            f"{w.get('reason', '')}｜伪ID {w.get('patient_pseudo_id', '-')}"
                            f"——不构成审核结论，不替代签字"})
    ingested = records_sink(gui_records)

    summary.update({
        "ok": True, "results": len(results), "ingested": ingested,
        "watchlist": screened["count"], "urgent": screened["urgent_count"],
        "leaks_blocked": len(de.leaks), "elapsed_sec": round(time.time() - t0, 2),
        "notice": screened["notice"],
    })
    if own and log:
        summary["audit_head"] = log.verify_chain()
    return summary


# ---------------------------------------------------------------------------
# 2) OCR 抽取：图片目录批量受理（后端缺失时如实降级）
# ---------------------------------------------------------------------------

def ocr_scan_dir(cfg: Dict[str, Any], actor_id: str,
                 records_sink: Callable[[List[Dict[str, Any]]], int],
                 audit_path: Optional[str] = None) -> Dict[str, Any]:
    d = cfg.get("dir") or ""
    if not d or not os.path.isdir(d):
        return {"ok": False, "error": f"图片目录不存在: {d}"}
    exts = (".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff")
    images = sorted(f for f in os.listdir(d) if f.lower().endswith(exts))
    backends = backend_status()
    available = [b for b in backends if b.get("available")]
    log = AuditLog(audit_path) if audit_path else None
    intake = OcrIntake(log=log, confidence_min=float(cfg.get("confidence_min", 0.80)))
    pending = []
    if available:
        for name in images:
            rec = intake.intake(os.path.join(d, name), actor_id=actor_id)
            pending.append(rec.as_dict())
        gui_records = [{"type": "待发列表",
                        "content": f"OCR 待人工确认：{p.get('image', '?')} 置信度 "
                                   f"{p.get('confidence', 0):.2f}（不构成审核结论）"}
                       for p in pending[:int(cfg.get("max_records", 200))]]
        ingested = records_sink(gui_records)
    else:
        # 引擎未装：如实降级为人工录入队列，不伪装识别成功
        gui_records = [{"type": "待发列表",
                        "content": f"OCR 引擎未安装，图片 {name} 转人工录入队列"}
                       for name in images[:10]]
        ingested = records_sink(gui_records) if gui_records else 0
    return {"ok": True, "images": len(images), "backends": backends,
            "available": [b.get("id") for b in available],
            "pending": len(pending), "ingested": ingested,
            "note": ("后端未安装：已按设计降级为人工录入队列（装 tesseract/"
                     "RapidOCR 后自动启用）") if not available else ""}


# ---------------------------------------------------------------------------
# 3) LIS 回写：仅连通性测试（回写默认禁止）
# ---------------------------------------------------------------------------

def lis_ping(cfg: Dict[str, Any]) -> Dict[str, Any]:
    host = cfg.get("host") or ""
    port = int(cfg.get("port", 0) or 0)
    if not host or not (0 < port < 65536):
        return {"ok": False, "error": "主机或端口无效"}
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=float(cfg.get("timeout", 5.0))):
            return {"ok": True, "endpoint": f"{host}:{port}",
                    "elapsed_ms": round((time.time() - t0) * 1000),
                    "note": "TCP 握手成功；结果回写仍为禁止状态，不向 LIS 下发任何数据"}
    except OSError as e:
        return {"ok": False, "endpoint": f"{host}:{port}", "error": str(e)}


# ---------------------------------------------------------------------------
# 4) 云端大模型：OpenAI 兼容连通性测试（不携带患者数据）
# ---------------------------------------------------------------------------

def llm_ping(cfg: Dict[str, Any]) -> Dict[str, Any]:
    base = (cfg.get("base_url") or "").rstrip("/")
    key = cfg.get("api_key") or ""
    model = cfg.get("model") or ""
    if not base or not key or not model:
        return {"ok": False, "error": "Base URL / API Key / 模型名 均必填"}
    url = f"{base}/chat/completions"
    payload = json.dumps({"model": model, "max_tokens": 1,
                          "messages": [{"role": "user", "content": "ping"}]}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {key}"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=float(cfg.get("timeout", 10.0))) as resp:
            body = resp.read(512)
            return {"ok": True, "http": resp.status, "model": model,
                    "elapsed_ms": round((time.time() - t0) * 1000),
                    "note": "连通正常；真实调用仅允许作用于脱敏后文本（文档 05 最小暴露面）"}
    except urllib.error.HTTPError as e:
        return {"ok": False, "http": e.code, "error": f"HTTP {e.code}: {e.reason[:120]}"}
    except Exception as e:  # 网络层错误（超时/DNS/拒绝）
        return {"ok": False, "error": f"{type(e).__name__}: {e}"[:160]}


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------

def selftest() -> int:
    print("== labbridge_apibridge 自检 ==")
    ok = True
    import tempfile

    # 1 配置合并
    cfg = merge_config({"astm_ingest": {"mode": "simulate"}})
    t1 = cfg["astm_ingest"]["mode"] == "simulate" and cfg["astm_ingest"]["tcp_port"] == 11000
    print(f"[1] 配置合并: {t1}")
    ok &= t1

    tmp = tempfile.mkdtemp(prefix="apib_")

    # 2 ASTM simulate 全链路灌入
    sink_items: List[Dict[str, Any]] = []
    def sink(recs):
        sink_items.extend(recs)
        return len(recs)
    audit = os.path.join(tmp, "api_audit.jsonl")
    s = astm_run(cfg["astm_ingest"], actor_id="selftest", role="technician",
                 records_sink=sink, audit_path=audit)
    t2 = bool(s.get("ok")) and s.get("results", 0) > 0 and len(sink_items) > 0
    print(f"[2] ASTM simulate 灌入: ok={s.get('ok')} 结果={s.get('results')} "
          f"待关注={s.get('watchlist')} 危急={s.get('urgent')} 落库={len(sink_items)}")
    ok &= t2

    # 3 落库记录类型与措辞合规
    types = {r["type"] for r in sink_items}
    bad_words = ("已审核", "已签发", "结论为")
    t3 = types <= {"检验结果", "待发列表"} and \
        not any(w in r["content"] for r in sink_items for w in bad_words)
    print(f"[3] 记录类型/措辞合规: types={sorted(types)} 合规={t3}")
    ok &= t3

    # 4 审计链可校验
    al = AuditLog(audit)
    v = al.verify_chain()
    print(f"[4] 审计链校验: {v.get('ok', v)}")
    ok &= bool(v.get("ok", False)) if isinstance(v, dict) else bool(v)

    # 5 LIS 连通性测试（连一个必然不通的地址，须优雅返回 not ok）
    p = lis_ping({"host": "127.0.0.1", "port": 1, "timeout": 2.0})
    print(f"[5] LIS 连通性(预期失败): ok={p['ok']} 优雅处理={p['ok'] is False}")
    ok &= p["ok"] is False

    # 6 LLM 连通性（缺 key 须优雅拒绝）
    l = llm_ping({"base_url": "https://example.invalid/v1", "api_key": "", "model": "x"})
    print(f"[6] LLM 缺参数拒绝: ok={l['ok']}")
    ok &= l["ok"] is False

    # 7 OCR 目录不存在须优雅拒绝；后端状态可见
    o = ocr_scan_dir({"dir": ""}, actor_id="selftest", records_sink=sink)
    print(f"[7] OCR 空目录拒绝: ok={o['ok']}")
    ok &= o["ok"] is False

    print("\n结果:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="LabBridge API 对接桥")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        raise SystemExit(selftest())
    print(__doc__)
