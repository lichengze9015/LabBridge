#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LabBridge 轨道 A —— ASTM E1381 / E1394 只读接收端（P0）· 纯标准库

Provenance / 反溯说明
---------------------
依据 ASTM E1381（低层协议：帧结构、校验和、会话握手）与 ASTM E1394
（应用层：H/P/O/R/L 记录结构）的**公开协议规范**独立编写。

为什么自研而不直接用社区包：
    文档 09 判定 `labmcp-astm-lis`（Apache-2.0）为唯一候选，但它是 ★20 的单人/小团队
    早期项目，属于**单点依赖**：上游消失或破坏性更新会直接击穿 Demo 技术底座。
    文档 09 给的建议是「fork + 锁版本 + 外面包一层自己的审计中间件」；
    而 E1381/E1394 是公开标准、帧结构极小，自研一套的成本低于长期维护一个 fork。
    因此这里自研接收端，并把 `labmcp-astm-lis` 降级为**可选适配器**（见文件末尾
    `LabMcpAdapter`），保留其能力但不构成依赖。

    本文件未参考 labmcp-astm-lis 或任何 ASTM 开源实现的源码。

文档 04 / 05 的硬约束（写进代码，不只是写进文档）：
    1. **只读旁路**——不向仪器发送查询或指令。默认 `passive` 模式一个字节都不写出；
       `handshake` 模式只允许发链路层 ACK/NAK/EOT，禁止发 ENQ（发起会话）
       与任何记录内容。每次写出都落审计日志。
    2. **落盘前脱敏**——接收端在交给下游之前即调用脱敏钩子（默认对 PII 字段掩码）。
    3. **全程留痕**——每条会话、每个记录、每个校验错误都落审计日志。

运行模式：
    passive     纯旁路侦听（串口 Tap 或交换机镜像口），零写出，最安全
    tcp         TCP listener，仪器作为 client 主动连入，需握手回 ACK
    serial      串口（需要 pyserial，未安装时给出明确提示）
    replay      回放已捕获的字节流（无硬件即可验证）
    simulate    生成合成 ASTM 会话（Demo 演示用，非真实数据）
"""

import os
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# ASTM E1381 控制字符
# ---------------------------------------------------------------------------
ENQ = 0x05
ACK = 0x06
NAK = 0x15
EOT = 0x04
STX = 0x02
ETX = 0x03
ETB = 0x17
CR = 0x0D
LF = 0x0A


def checksum(payload: bytes) -> str:
    """ASTM E1381 校验和：STX 之后到 ETX/ETB（含）的字节和 mod 256，2 位大写十六进制。"""
    return f"{sum(payload) & 0xFF:02X}"


# 报文编解码字符集。E1381 名义上是 ASCII，但国内仪器普遍发 GBK，
# 接入真实仪器时须确认其字符集并用环境变量覆盖，否则中文姓名会变问号。
# V3.1：改为按调用时读取（原为 import 时固化常量，GUI 内按连接配置切换字符集无效）
def _codec() -> str:
    return os.environ.get("LABBRIDGE_ASTM_CODEC", "utf-8")


def build_frame(seq: int, text: str, last: bool = False) -> bytes:
    """构造一帧。`seq` 为 0-7 循环帧号。"""
    body = text.encode(_codec(), errors="replace")
    payload = bytes([STX]) + str(seq % 8).encode() + body + bytes([ETX if last else ETB])
    return payload + checksum(payload[1:]).encode() + bytes([CR, LF])


@dataclass
class Frame:
    seq: int
    text: str
    last: bool
    ok: bool
    error: str = ""


def parse_frame(raw: bytes) -> Frame:
    """解析一帧。校验和错误时 ok=False，但仍返回内容以便审计定位。"""
    if len(raw) < 5 or raw[0] != STX:
        return Frame(-1, "", False, False, "帧头非 STX")
    core = raw[1:]
    # 找到终止符 ETX / ETB
    end_idx = -1
    last = False
    for i, b in enumerate(core):
        if b in (ETX, ETB):
            end_idx = i
            last = (b == ETX)
            break
    if end_idx < 1:
        return Frame(-1, "", False, False, "缺少 ETX/ETB")
    try:
        seq = int(chr(core[0]))
    except ValueError:
        return Frame(-1, "", False, False, "帧号非法")
    text = core[1:end_idx].decode(_codec(), errors="replace")
    # 校验和覆盖「帧号 + 正文 + 终止符」，与 build_frame 的 checksum(payload[1:]) 对齐
    measured = core[0:end_idx + 1]
    expect = raw[end_idx + 2:end_idx + 4].decode("ascii", errors="replace")
    got = checksum(measured)
    if expect.upper() != got:
        return Frame(seq, text, last, False, f"校验和不符 期望{got} 实收{expect}")
    return Frame(seq, text, last, True)


# ---------------------------------------------------------------------------
# ASTM E1394 记录层
# ---------------------------------------------------------------------------

@dataclass
class Record:
    type: str
    fields: List[str]

    def get(self, idx: int, comp: int = 0, default: str = "") -> str:
        """取字段。E1394 字段从 1 开始编号；组件用 ^ 分隔。"""
        try:
            raw = self.fields[idx - 1]
        except IndexError:
            return default
        if comp:
            parts = raw.split("^")
            try:
                return parts[comp - 1]
            except IndexError:
                return default
        return raw


def parse_records(text: str) -> List[Record]:
    """把一帧或多帧拼接的文本切分为记录行。"""
    out: List[Record] = []
    for line in text.split("\r"):
        line = line.strip("\n").strip()
        if not line:
            continue
        parts = line.split("|")
        rtype = parts[0].strip().upper()
        if len(rtype) == 1 and rtype.isalpha():
            out.append(Record(rtype, parts))
    return out


# E1394 R 记录字段位（常用）
#  2 结果在记录中的序号  3 项目代码^...  4 结果值  5 单位  6 参考区间  7 异常标志
_R_SEQ, _R_TEST, _R_VALUE, _R_UNIT, _R_REF, _R_FLAG = 2, 3, 4, 5, 6, 7


def _to_float(v: str) -> Optional[float]:
    try:
        return float(str(v).replace("<", "").replace(">", "").replace("=", "").strip())
    except (TypeError, ValueError):
        return None


# E1394 P 记录字段位存在两种常见习惯：
#   习惯 A（E1394 正文）: P.3/4 患者号、P.5/6 姓名、P.7 出生日期、P.8 性别
#   习惯 B（常见实机）  : P.4 患者号、P.6 姓名、P.8 出生日期、P.9 性别
# 真实仪器出厂实现并不统一，这里做**容错读取**而不是赌某一种：
# 按候选位依次取第一个「形态匹配」的值。正式接入某台仪器时，
# 必须在调试阶段用真实报文确认该仪器的字段位，并把结论写进本模块的调试记录。
P_ID_FIELDS = (3, 4)
P_NAME_FIELDS = (5, 6)
P_DOB_FIELDS = (7, 8)
P_SEX_FIELDS = (9, 8)
SEX_VALUES = {"M", "F", "U", "O", "男", "女"}


def _first_match(rec: "Record", fields, predicate) -> str:
    for idx in fields:
        v = (rec.get(idx) or "").strip()
        if v and predicate(v):
            return v
    return ""


def message_to_results(records: List[Record], source: str = "astm") -> List[Dict[str, Any]]:
    """E1394 记录 → 统一结果模型（文档 04 第三章）。

    统一模型字段：患者伪 ID、性别、项目、结果值、单位、参考区间、异常标志、仪器注释。
    注意：P 记录中的姓名/出生日期在此**保留原值**交下游，由脱敏引擎按规则处理，
    接收端不自行决定「什么是敏感」——规则归人，执行归机器（文档 05 第一章）。
    """
    results: List[Dict[str, Any]] = []
    patient_id, sex, patient_name, dob = "", "", "", ""
    order_id = ""
    for r in records:
        if r.type == "P":
            patient_id = _first_match(r, P_ID_FIELDS, lambda v: True) or patient_id
            patient_name = _first_match(r, P_NAME_FIELDS,
                                        lambda v: not v.replace("^", "").isdigit())
            dob = _first_match(r, P_DOB_FIELDS, lambda v: bool(re.match(r"^\d{8}$", v)))
            sex = _first_match(r, P_SEX_FIELDS, lambda v: v.upper() in SEX_VALUES)
        elif r.type == "O":
            # E1394：O.2 为记录序号，O.3 为标本号，O.4 为仪器标本号。
            # 必须优先取 O.3，否则会把序号「1」当成标本号，导致所有标本塌缩成一份。
            order_id = r.get(3) or r.get(4) or order_id
        elif r.type == "R":
            test_raw = r.get(_R_TEST)
            # R.3 形如 "^^^K" 或 "^^^^WBC^1234"：项目码通常在第 4 组件，
            # 也有仪器直接给裸码。优先取第 4 组件，回退取首个非空组件。
            comps = test_raw.split("^")
            test_code = (comps[3] if len(comps) >= 4 and comps[3].strip() else "")
            if not test_code:
                test_code = next((c.strip() for c in comps if c.strip()), "")
            results.append({
                "patient_pseudo_id": patient_id,
                "patient_name": patient_name,
                "dob": dob,
                "sex": sex,
                "specimen_id": order_id,
                "test_item": test_code,
                "test_item_raw": test_raw,
                "result_value": _to_float(r.get(_R_VALUE)),
                "result_value_raw": r.get(_R_VALUE),
                "unit": r.get(_R_UNIT),
                "ref_range": r.get(_R_REF),
                "abnormal_flag": r.get(_R_FLAG).strip().upper(),
                "instrument_note": "",
                "data_source": source,
            })
        elif r.type == "C":
            # C.3 注释来源（I=仪器），C.4 注释正文
            if results:
                results[-1]["instrument_note"] = (results[-1]["instrument_note"] +
                                                  " " + r.get(4)).strip()
    return results


# ---------------------------------------------------------------------------
# 接收端
# ---------------------------------------------------------------------------

class ReadOnlyViolation(Exception):
    """试图向仪器下发查询或指令。"""


class AstmReceiver:
    """只读 ASTM 接收端。

    mode:
        passive   零写出（旁路侦听/镜像口）
        tcp       TCP listener，允许链路层 ACK/NAK/EOT
        serial    串口（需 pyserial）
        replay    回放字节流
        simulate  合成会话
    """

    FORBIDDEN_OUTBOUND = {ENQ: "ENQ（发起会话=查询）"}

    def __init__(self, mode: str = "replay", log=None, receive_timeout: float = 30.0):
        self.mode = mode
        self.log = log                      # AuditLog，可为 None（演示降级）
        self.receive_timeout = receive_timeout
        self.sessions: List[Dict[str, Any]] = []
        self.frames_ok = 0
        self.frames_bad = 0
        self.records: List[Record] = []
        self._buffer = bytearray()
        self._stop = threading.Event()

    # -- 审计 ---------------------------------------------------------------

    def _audit(self, action: str, **kw: Any) -> None:
        if self.log is None:
            return
        try:
            self.log.record(action, data_source="astm", **kw)
        except Exception:
            pass

    # -- 字节流处理 ---------------------------------------------------------

    def feed_bytes(self, data: bytes, out: Optional[Callable[[bytes], None]] = None) -> Dict[str, Any]:
        """喂入字节流。返回本次解析出的事件摘要。

        `out` 是可选的写出回调（仅 handshake 模式需要）。
        """
        events: List[Dict[str, Any]] = []
        for b in data:
            if b == ENQ:
                events.append({"type": "enq"})
                self._audit("receive", object="ENQ", result="ok")
                if out:
                    self._write(out, bytes([ACK]), "ACK(链路层)")
                continue
            if b == EOT:
                events.append({"type": "eot"})
                self.sessions.append({"ended_at": time.time(), "frames": self.frames_ok})
                self._audit("receive", object="EOT", result="ok")
                continue
            if b == STX:
                self._buffer = bytearray([STX])
                continue
            if self._buffer and self._buffer[0] == STX:
                self._buffer.append(b)
                if self._frame_complete():
                    self._consume_frame(events, out)
                elif len(self._buffer) > 8192:
                    # 无终结符时防无限增长
                    self._buffer = bytearray()
        return {"events": events, "frames_ok": self.frames_ok, "frames_bad": self.frames_bad}

    def _frame_complete(self) -> bool:
        """判断是否已收完整帧。

        注意：E1394 的**记录分隔符本身就是 CR**，所以不能「见到第一个 CR 就收帧」——
        那会在第一条记录后误截断。帧的真正结尾是：
            ... ETX|ETB <CHK1> <CHK2> CR [LF]
        末尾 5 字节形态为 ETX/ETB + 2 校验字符 + CR 时为完整帧。
        """
        buf = self._buffer
        if len(buf) < 5:
            return False
        if buf[-1] == LF and len(buf) >= 6 and buf[-2] == CR and buf[-5] in (ETX, ETB):
            return True
        if buf[-1] == CR and len(buf) >= 5 and buf[-4] in (ETX, ETB):
            return True
        return False

    def _consume_frame(self, events: List[Dict[str, Any]],
                       out: Optional[Callable[[bytes], None]]) -> None:
        frame = parse_frame(bytes(self._buffer))
        if frame.ok:
            self.frames_ok += 1
            recs = parse_records(frame.text)
            self.records.extend(recs)
            events.append({"type": "frame", "seq": frame.seq,
                           "records": len(recs), "last": frame.last})
            self._audit("receive", object=f"frame#{frame.seq}",
                        result="ok", extra={"records": len(recs)})
            if out:
                self._write(out, bytes([ACK]), f"ACK(帧{frame.seq})")
        else:
            self.frames_bad += 1
            events.append({"type": "frame_error", "error": frame.error})
            self._audit("receive", object=f"frame#{frame.seq}",
                        result="error", extra={"error": frame.error})
            if out:
                self._write(out, bytes([NAK]), "NAK(校验失败)")
        self._buffer = bytearray()

    def _write(self, out: Callable[[bytes], None], payload: bytes, why: str) -> None:
        """唯一的写出通道。只放行链路层握手字节。"""
        if self.mode == "passive":
            raise ReadOnlyViolation(
                f"passive 模式禁止任何写出（试图发送 {why}）——文档 04：只读旁路，不下发指令")
        for b in payload:
            if b in self.FORBIDDEN_OUTBOUND:
                raise ReadOnlyViolation(
                    f"禁止向仪器发送 {self.FORBIDDEN_OUTBOUND[b]}——文档 04/07：只读旁路")
        self._audit("link_write", object=why, result="ok",
                    extra={"bytes": payload.hex()})
        out(payload)

    # -- 各模式入口 ---------------------------------------------------------

    def run_tcp(self, host: str = "0.0.0.0", port: int = 11000,
                max_sessions: int = 1, timeout: float = None) -> Dict[str, Any]:
        """TCP listener。仪器作为 client 连入。"""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(1)
        srv.settimeout(timeout or self.receive_timeout)
        self._audit("listen", object=f"{host}:{port}", result="ok")
        summary = {"mode": "tcp", "endpoint": f"{host}:{port}", "sessions": 0}
        try:
            while summary["sessions"] < max_sessions and not self._stop.is_set():
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    break
                with conn:
                    conn.settimeout(timeout or self.receive_timeout)
                    out = conn.sendall if self.mode == "tcp" else None
                    while not self._stop.is_set():
                        try:
                            chunk = conn.recv(4096)
                        except socket.timeout:
                            break
                        if not chunk:
                            break
                        self.feed_bytes(chunk, out)
                summary["sessions"] += 1
        finally:
            srv.close()
        summary.update({"frames_ok": self.frames_ok, "frames_bad": self.frames_bad,
                        "records": len(self.records)})
        return summary

    def run_serial(self, port: str, baud: int = 9600, timeout: float = None) -> Dict[str, Any]:
        try:
            import serial  # type: ignore
        except ImportError:
            raise RuntimeError("serial 模式需要 pyserial：pip install pyserial（Apache-2.0）")
        with serial.Serial(port, baud, timeout=timeout or self.receive_timeout) as s:
            deadline = time.time() + (timeout or self.receive_timeout)
            out = s.write if self.mode == "tcp" else None   # 串口旁路默认不握手
            while time.time() < deadline and not self._stop.is_set():
                chunk = s.read(4096)
                if not chunk:
                    continue
                self.feed_bytes(chunk, out)
        return {"mode": "serial", "port": port, "frames_ok": self.frames_ok,
                "frames_bad": self.frames_bad, "records": len(self.records)}

    def run_replay(self, path: str) -> Dict[str, Any]:
        with open(path, "rb") as f:
            self.feed_bytes(f.read())
        return {"mode": "replay", "file": path, "frames_ok": self.frames_ok,
                "frames_bad": self.frames_bad, "records": len(self.records)}

    def stop(self) -> None:
        self._stop.set()

    def results(self) -> List[Dict[str, Any]]:
        return message_to_results(self.records)


# ---------------------------------------------------------------------------
# 合成会话（无硬件演示用）
# ---------------------------------------------------------------------------

_SAMPLE_PANEL = [
    ("WBC", 6.4, "10^9/L", "4.0-10.0"),
    ("RBC", 4.51, "10^12/L", "3.8-5.1"),
    ("HGB", 132.0, "g/L", "115-150"),
    ("PLT", 210.0, "10^9/L", "125-350"),
    ("K", 4.1, "mmol/L", "3.5-5.3"),
    ("GLU", 5.6, "mmol/L", "3.9-6.1"),
]


def simulate_session(n_samples: int = 50, seed: int = 20261022,
                     critical_every: int = 0) -> bytes:
    """生成一段合成 ASTM E1381/E1394 会话字节流，用于无硬件验证与演示。

    注意：这是**合成数据**，用于验证链路与规则引擎，不是真实患者数据。
    文档 02 目标 3 的「≥50 份标本」实测必须用真实/脱敏真实数据，不能拿它充数。
    """
    import random
    rnd = random.Random(seed)
    buf = bytearray([ENQ])
    seq = 1
    now = time.strftime("%Y%m%d%H%M%S")

    def emit(text: str) -> None:
        nonlocal seq
        # 每帧最多 ~200 字符，这里按记录逐条成帧
        buf.extend(build_frame(seq % 8, text + "\r", last=True))
        seq += 1

    emit(f"H|\\^&|||Mindray^BC-2800^1.0|||||host||P|1|{now}")
    for i in range(1, n_samples + 1):
        sid = f"S{i:05d}"
        pid = f"P{i:05d}"
        # 合成患者姓名（显式标注为合成数据，避免与真实信息混淆）
        emit(f"P|1||{pid}||合成{i}号^测试||{now[:8]}|{'M' if i % 2 else 'F'}")
        emit(f"O|1|{sid}||{','.join(t[0] for t in _SAMPLE_PANEL)}|R")
        for j, (code, base, unit, ref) in enumerate(_SAMPLE_PANEL, start=1):
            value = round(base * rnd.uniform(0.75, 1.25), 2)
            flag = ""
            if critical_every and i % critical_every == 0 and code == "K":
                value = 7.3
                flag = "H"
            elif value < base * 0.85:
                flag = "L"
            elif value > base * 1.15:
                flag = "H"
            emit(f"R|{j}|^^^{code}|{value}|{unit}|{ref}|{flag}||F||{now}")
        emit("L|1|N")
    buf.append(EOT)
    return bytes(buf)


# ---------------------------------------------------------------------------
# 可选适配器：社区包 labmcp-astm-lis（Apache-2.0）
# ---------------------------------------------------------------------------

class LabMcpAdapter:
    """把社区包 `labmcp-astm-lis` 作为**可选**接收后端。

    按文档 09 的建议：它现在可用（Apache-2.0、能力匹配），但 ★20 属早期项目，
    因此本项目不把它作为依赖——只做适配接口，装了就能用，没装就走自研接收端。
    用它时同样必须套上本项目的审计日志与脱敏钩子，不能依赖它的默认行为
    （文档 09：「别依赖上游默认值，外审要拿出自己签署的规则文件」）。
    """

    PACKAGE = "labmcp_astm_lis"
    LICENSE = "Apache-2.0"
    UPKEEP_NOTE = "★20 早期项目：使用前应 fork 并锁定 commit hash"

    @classmethod
    def available(cls) -> bool:
        import importlib.util
        return importlib.util.find_spec(cls.PACKAGE) is not None

    @classmethod
    def status(cls) -> Dict[str, Any]:
        return {"package": cls.PACKAGE, "available": cls.available(),
                "license": cls.LICENSE, "note": cls.UPKEEP_NOTE,
                "required": False, "fallback": "AstmReceiver（本项目自研）"}


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------

def selftest() -> int:
    print("== labbridge_astm 自检 ==")
    ok = True

    # 1 帧编解码 + 校验和
    text = "R|1|^^^K|4.1|mmol/L|3.5-5.3||F||20261022120000"
    fr = build_frame(1, text + "\r", last=True)
    p = parse_frame(fr)
    print(f"[1] 帧往返: seq={p.seq} ok={p.ok} last={p.last}")
    ok &= p.ok and p.seq == 1 and p.last and p.text.strip("\r") == text

    bad = bytearray(fr)
    bad[-4] = ord("0") if chr(bad[-4]) != "0" else ord("1")
    pb = parse_frame(bytes(bad))
    print(f"[2] 校验和错误可检出: ok={pb.ok} err={pb.error}")
    ok &= (not pb.ok)

    # 2 记录解析
    recs = parse_records(
        "H|\\^&|||Mindray^BC-2800|||||host||P|1|20261022120000\r"
        "P|1||P00001||张三^三||19900101|M\r"
        "O|1|S00001|||R\r"
        "R|1|^^^K|7.3|mmol/L|3.5-5.3|H||F\r"
        "C|1|I|样本溶血\r"
        "L|1|N\r")
    types = [r.type for r in recs]
    print(f"[3] 记录切分: {types}")
    ok &= types == ["H", "P", "O", "R", "C", "L"]

    res = message_to_results(recs)
    r0 = res[0]
    print(f"[4] 统一模型: pid={r0['patient_pseudo_id']} item={r0['test_item']} "
          f"val={r0['result_value']} flag={r0['abnormal_flag']} note={r0['instrument_note']}")
    ok &= (r0["patient_pseudo_id"] == "P00001" and r0["test_item"] == "K"
           and r0["result_value"] == 7.3 and r0["abnormal_flag"] == "H"
           and "溶血" in r0["instrument_note"])

    # 3 合成会话端到端
    stream = simulate_session(n_samples=3, seed=7)
    rx = AstmReceiver(mode="replay")
    summary = rx.feed_bytes(stream)
    got = rx.results()
    print(f"[5] 合成会话: frames_ok={summary['frames_ok']} bad={summary['frames_bad']} "
          f"records={len(rx.records)} results={len(got)}")
    ok &= summary["frames_bad"] == 0 and len(got) == 3 * len(_SAMPLE_PANEL)

    # 4 只读约束
    rx2 = AstmReceiver(mode="passive")
    try:
        rx2.feed_bytes(bytes([ENQ]), out=lambda b: None)
        print("[6] passive 模式写出: FAIL（未拦截）")
        ok = False
    except ReadOnlyViolation:
        print("[6] passive 模式零写出: OK（拦截成功）")

    rx3 = AstmReceiver(mode="tcp")
    sent = bytearray()
    rx3.feed_bytes(simulate_session(n_samples=1), out=sent.extend)
    print(f"[7] handshake 模式仅回 ACK: {sent.hex()} (仅 06=ACK)")
    ok &= all(b == ACK for b in sent) and len(sent) > 0

    try:
        rx3._write(lambda b: None, bytes([ENQ]), "ENQ")
        print("[8] 禁止下发 ENQ: FAIL（未拦截）")
        ok = False
    except ReadOnlyViolation:
        print("[8] 禁止下发 ENQ: OK（拦截成功）")

    # 5 社区包适配器状态
    st = LabMcpAdapter.status()
    print(f"[9] 社区包适配器: available={st['available']} required={st['required']} "
          f"fallback={st['fallback']}")
    ok &= st["required"] is False

    print("结果:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
