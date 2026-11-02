# -*- coding: utf-8 -*-
"""
LabBridge V2 封包主应用（GUI）
依据《V2优化项.txt》13 条对 V1 重新封包。

落点对照（V2优化项 → 本文件）:
  1  4 个预留 API 接口 UI 开关            → ApiPanel / APIGateV2
  3  工程师/主任/组长/检验员 人员增删      → PeoplePanel
  4  撤回/审核/删除按钮                   → RecordsPanel
  5  4 级权限 1111/2222/3333/4444        → USERS
  6  全套证据包自动生成+签名栏/日期栏      → EvidencePanel.build_evidence_pack
  7  DEMO 无法律效力声明/不合适项标注      → DEMO_DISCLAIMER / NOT_SUITABLE_ITEMS
  8  工程师操作日志不对外直接输出          → OpsLog.internal（仅留痕，不导出）
  9  数据日志与操作日志分离               → data_log.jsonl / op_log.jsonl
  10 敏感信息查看主任密码确认             → SensitiveViewer
  11 云端客户自指定+风险提示             → CloudPanel
  12 哈希/event_id 溯源查询              → TracePanel
  13 风险热力图 L×C 九宫格 + PDCA 单独封包 → HeatmapPanel / pdca 封包

零第三方依赖（纯标准库 + tkinter），可离线运行。
"""
import base64
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

APP_TITLE = "LabBridge V2 检验数据治理 DEMO"
APP_VERSION = "2.5.2"
DEMO_DISCLAIMER = ("【DEMO 声明】本文件由 DEMO 工具自动生成与记录，无实地人员真实签字，"
                   "不具备法律法规意义，仅作为 DEMO 输出展示项。")
NOT_SUITABLE_ITEMS = [
    "多底座对比分析报告",
    "专项风险评估报告",
    "准入边界文件",
    "全套证据包（操作日志/人工审核记录/版本变更记录/CAPA 整改记录）",
]
SOP_RISK_NOTE_10 = ("SOP 风险项说明：敏感·患者身份信息例外查看若由主任单人密码确认，"
                    "缺少双人复核控制，存在单人越权风险，须在 SOP 中登记为受控偏差。"
                    "（软件按 DEMO 设计不弹窗提示，此处为静态说明。）")
CLOUD_RISK_NOTE = ("风险/不适用提示：云端由客户自行指定（医院内网/局域网/外网/外置服务器均可），"
                   "“厂家”不额外提供云端；DEMO 仅搭配可能配置的端口示意，外网/外置服务器场景"
                   "不适用于等保与内网管控假设，相关成本由客户提供。")

# ---------------------------------------------------------------- 基础层

_TZ_OFFSET = time.strftime("%z")  # 例如 +0800


def now_iso() -> str:
    """带时区偏移的 ISO 8601（V2.4：跨机比对证据时必须能确定时区）。"""
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
    if _TZ_OFFSET and len(_TZ_OFFSET) == 5:
        return base + _TZ_OFFSET[:3] + ":" + _TZ_OFFSET[3:]
    return base


def ts_name() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def sha256_of(obj) -> str:
    return hashlib.sha256(json.dumps(obj, ensure_ascii=False, sort_keys=True,
                                     default=str).encode("utf-8")).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# V2.4：所有落盘写操作共用一把锁（GUI 主线程 + 后台接收线程会并发写）
_IO_LOCK = threading.RLock()


def _atomic_write(path: str, text: str) -> None:
    """原子写：先写同目录临时文件再替换，避免断电/并发产生半截文件。"""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".lb_tmp_", suffix=".part")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _atomic_write_json(path: str, obj) -> None:
    _atomic_write(path, json.dumps(obj, ensure_ascii=False, indent=2))

# 冻结（EXE）环境下，数据目录放 exe 同级；开发环境放源码同级
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HOME_DIR = os.path.join(BASE_DIR, "v2_data")
os.makedirs(HOME_DIR, exist_ok=True)


# ---------------------------------------------------------------- 受控配置完整性（V2.4）
# 背景：config/ 下是“人签署的受控文件”（危急值阈值、分级规则、角色矩阵…）。
# 旧实现只把它们当普通文件读，改一个字也没人知道。这里加一层 SHA-256 清单：
#   签署 = 工程师确认后写入 SHA256SUMS；校验 = 启动时逐文件比对。
# 边界：这只能发现“文件被改”，不能防“改完再重签”——重签本身也要工程师密码并留痕。
def _resolve_app_config_dir() -> str:
    env = os.environ.get("LABBRIDGE_CONFIG")
    if env:
        return os.path.normpath(env)
    if getattr(sys, "frozen", False):
        for cand in (os.path.join(BASE_DIR, "config"),
                     os.path.normpath(os.path.join(BASE_DIR, "..", "config"))):
            if os.path.isdir(cand):
                return cand
    local = os.path.join(BASE_DIR, "config")
    if os.path.isdir(local):
        return local
    return os.path.normpath(os.path.join(BASE_DIR, "..", "config"))


CONFIG_DIR_APP = _resolve_app_config_dir()
CONFIG_MANIFEST = os.path.join(CONFIG_DIR_APP, "SHA256SUMS")


def config_file_list() -> list:
    try:
        names = os.listdir(CONFIG_DIR_APP)
    except OSError:
        return []
    return sorted(n for n in names
                  if os.path.isfile(os.path.join(CONFIG_DIR_APP, n))
                  and n != "SHA256SUMS" and not n.startswith("."))


def config_hashes() -> dict:
    return {n: sha256_file(os.path.join(CONFIG_DIR_APP, n)) for n in config_file_list()}


def verify_config_integrity() -> dict:
    """返回 {ok, status, changed, missing, extra, signed_by, signed_at, reason,
    resign_count, superseded, signed_count}。

    status: signed（一致）/ mismatch（被改动）/ unsigned（未签署）/ unavailable（无配置目录）

    V2.5：解析头部元信息。重签次数与「被覆盖的原签署人」是判断“签署主体是否被
    本地替换”的唯一线索——只看哈希一致无法区分“发布方签的”与“操作员改完再签的”。
    """
    if not os.path.isdir(CONFIG_DIR_APP):
        return {"ok": False, "status": "unavailable", "changed": [], "missing": [], "extra": []}
    if not os.path.isfile(CONFIG_MANIFEST):
        return {"ok": False, "status": "unsigned", "changed": [],
                "missing": [], "extra": config_file_list()}
    meta = {}
    signed = {}
    try:
        with open(CONFIG_MANIFEST, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    body = line[1:].strip()
                    k, sep, v = body.partition("：")
                    if not sep:
                        k, sep, v = body.partition(":")
                    k, v = k.strip(), v.strip()
                    if k == "签署人":
                        meta["signed_by"] = v
                    elif k == "签署时间":
                        meta["signed_at"] = v
                    elif k == "变更原因":
                        meta["reason"] = v
                    elif k == "重签次数":
                        try:
                            meta["resign_count"] = int(v)
                        except ValueError:
                            meta["resign_count"] = 0
                    elif k == "覆盖原签署":
                        meta["superseded"] = v
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    signed[parts[1].strip()] = parts[0].strip()
    except OSError as e:
        return {"ok": False, "status": "mismatch", "changed": [f"无法读取清单：{e}"],
                "missing": [], "extra": []}
    actual = config_hashes()
    changed = [n for n in signed if n in actual and actual[n] != signed[n]]
    missing = [n for n in signed if n not in actual]
    extra = [n for n in actual if n not in signed]
    ok = not (changed or missing or extra)
    res = {"ok": ok, "status": "signed" if ok else "mismatch",
           "changed": changed, "missing": missing, "extra": extra,
           "signed_count": len(signed)}
    res.update(meta)
    return res


def sign_config_integrity(actor: str, reason: str = "") -> str:
    """按当前文件内容重新签署（调用方负责先做工程师密码确认并写审计）。

    V2.5 加固：记录变更原因、累计重签次数、保留被覆盖的原签署人。
    哈希清单只能证明“文件与签署时一致”，证明不了“是谁该签”。把重签次数与原签署人
    写进清单头部，审计方才能看出这份配置是否被本地操作员覆盖过发布方签署。
    """
    if os.path.isfile(CONFIG_MANIFEST):
        prev = verify_config_integrity()
        resign_n = int(prev.get("resign_count", 0) or 0) + 1
    else:
        prev, resign_n = {}, 0
    prev_by = str(prev.get("signed_by") or "")
    lines = ["# LabBridge 受控配置 SHA-256 清单",
             f"# 签署人：{actor}",
             f"# 签署时间：{now_iso()}",
             f"# 变更原因：{reason.strip() or '（未填写）'}",
             f"# 重签次数：{resign_n}"]
    if prev_by and prev_by != actor:
        lines.append(f"# 覆盖原签署：{prev_by}")
    lines.append("# 格式：<sha256>  <文件名>")
    for name, digest in sorted(config_hashes().items()):
        lines.append(f"{digest}  {name}")
    _atomic_write(CONFIG_MANIFEST, "\n".join(lines) + "\n")
    return CONFIG_MANIFEST

# V3.1：API 对接桥（4 个接口的真实对接层，code/ 下核心模块复用）
_CODE_DIR = os.path.join(BASE_DIR, "code")
if os.path.isdir(_CODE_DIR) and _CODE_DIR not in sys.path:
    sys.path.insert(0, _CODE_DIR)
try:
    import labbridge_apibridge as apib
    API_BRIDGE_OK = True
except Exception as _apib_err:  # 模块缺失时 API 页降级为仅开关
    apib = None
    API_BRIDGE_OK = False
    API_BRIDGE_ERR = str(_apib_err)

USERS_FILE = os.path.join(HOME_DIR, "users.json")
DATA_LOG = os.path.join(HOME_DIR, "data_log.jsonl")   # 优化9：数据结果日志
OP_LOG = os.path.join(HOME_DIR, "op_log.jsonl")        # 优化9：人员操作日志（内部留痕，不对外直接输出）
RECORDS_FILE = os.path.join(HOME_DIR, "records.json")

# 优化5：4 级权限账户（DEMO 同级别完全一样）
# V2.2.2 修复：层级唯一权威定义 ROLE_LEVEL（1=最高），显示/新建/校验三处共用，杜绝双体系紊乱
# 层级：L1 工程师 > L2 主任 > L3 组长 > L4 检验员；管理规则：Ln 可管理 L≥n（同级及以下），低层级不可反向管理高层级
ROLE_LEVEL = {"engineer": 1, "director": 2, "leader": 3, "technician": 4}
DEFAULT_USERS = [
    {"username": "工程师", "role": "engineer",  "password": "1111", "level": ROLE_LEVEL["engineer"]},
    {"username": "组长",   "role": "leader",    "password": "2222", "level": ROLE_LEVEL["leader"]},
    {"username": "主任",   "role": "director",  "password": "3333", "level": ROLE_LEVEL["director"]},
    {"username": "检验员", "role": "technician","password": "4444", "level": ROLE_LEVEL["technician"]},
]
ROLE_NAMES = {"engineer": "工程师", "leader": "组长", "director": "主任", "technician": "检验员"}

def load_users():
    with _IO_LOCK:
        if not os.path.exists(USERS_FILE):
            save_users(DEFAULT_USERS)
            return [dict(u) for u in DEFAULT_USERS]
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                users = json.load(f)
        except (OSError, ValueError):
            # 文件损坏时不要静默覆盖：先备份坏文件，再回退默认账户
            try:
                shutil.copy2(USERS_FILE, USERS_FILE + ".broken_" + ts_name())
            except OSError:
                pass
            save_users(DEFAULT_USERS)
            return [dict(u) for u in DEFAULT_USERS]
    # V2.2.1 迁移：历史数据的 level 属性若与 ROLE_LEVEL 不一致，按角色统一校正并落盘
    changed = False
    plain_on_disk = False
    for u in users:
        lv = ROLE_LEVEL.get(u.get("role"))
        if lv is not None and u.get("level") != lv:
            u["level"] = lv
            changed = True
        # V2.5：口令落盘混淆。读到 enc:v1: 就解密；读到明文则标记迁移，写回时自动加密。
        pw = u.get("password")
        if isinstance(pw, str) and pw.startswith("enc:v1:"):
            u["password"] = reveal_secret(pw)
        elif pw:
            plain_on_disk = True
    if changed or plain_on_disk:
        save_users(users)
    return users


def _users_for_disk(users):
    """落盘前把口令混淆；已混淆的不重复处理（避免二次加密）。"""
    out = []
    for u in users:
        v = dict(u)
        pw = str(v.get("password") or "")
        if pw and not pw.startswith("enc:v1:"):
            v["password"] = protect_secret(pw)
        out.append(v)
    return out


def save_users(users):
    with _IO_LOCK:
        _atomic_write_json(USERS_FILE, _users_for_disk(users))

# ---------------------------------------------------------------- 日志（哈希链，双轨分离）

class HashChainLog:
    """哈希链日志（V2.4 改造）。

    相对旧实现的三个变化：
    1. **线程安全**：append 全程持 `_IO_LOCK`，后台接收线程与主线程不会争抢
       链头（旧实现先读 self.records[-1] 再写文件，并发时会产生同 seq 双胞胎
       或 prev_hash 指向错误 → 链断）。
    2. **分段轮转**：单文件达到 ROTATE_BYTES 后改名 <name>.NNNNNN.jsonl 归档，
       新文件首条记录仍以归档末条 hash 为 prev_hash，跨段链不断。
    3. **流式读取**：不再启动时全量载入内存；query / verify / export 逐行扫描。
       旧实现日志越长启动越慢、内存越大。
    """

    ROTATE_BYTES = 5 * 1024 * 1024

    def __init__(self, path: str):
        self.path = path
        self.dir = os.path.dirname(os.path.abspath(path)) or "."
        self.base = os.path.basename(path)
        self.internal = self.base == "op_log.jsonl"
        self._head = None  # (seq, hash)

    # -- 分段 ---------------------------------------------------------------
    def _archive_files(self) -> list:
        prefix = self.base + "."
        found = []
        try:
            names = os.listdir(self.dir)
        except OSError:
            return []
        for n in names:
            if n.startswith(prefix) and n.endswith(".jsonl"):
                mid = n[len(prefix):-len(".jsonl")]
                if mid.isdigit():
                    found.append((int(mid), os.path.join(self.dir, n)))
        return [p for _, p in sorted(found)]

    def segments(self) -> list:
        segs = self._archive_files()
        if os.path.exists(self.path):
            segs.append(self.path)
        return segs

    # -- 链头 ---------------------------------------------------------------
    def _read_last(self):
        for seg in reversed(self.segments()):
            try:
                size = os.path.getsize(seg)
                with open(seg, "rb") as f:
                    f.seek(max(0, size - 65536))
                    tail = f.read().decode("utf-8", errors="replace")
            except OSError:
                continue
            for line in reversed([x for x in tail.splitlines() if x.strip()]):
                try:
                    r = json.loads(line)
                    return int(r.get("seq", 0)), r.get("hash", "GENESIS")
                except Exception:
                    continue
        return 0, "GENESIS"

    def head(self):
        with _IO_LOCK:
            if self._head is None:
                self._head = self._read_last()
            return self._head

    # -- 写 -----------------------------------------------------------------
    def _rotate_if_needed(self):
        try:
            if os.path.exists(self.path) and os.path.getsize(self.path) >= self.ROTATE_BYTES:
                n = 0
                for p in self._archive_files():
                    n = max(n, int(os.path.basename(p)[len(self.base) + 1:-len(".jsonl")]))
                os.replace(self.path, os.path.join(self.dir, f"{self.base}.{n + 1:06d}.jsonl"))
        except OSError:
            pass  # 轮转失败不影响写入；下次再试

    def append(self, action: str, actor: str, role: str, detail: dict) -> dict:
        with _IO_LOCK:
            seq, prev = self.head()
            rec = {
                "seq": seq + 1,
                "event_id": uuid.uuid4().hex[:16],
                "ts": now_iso(),
                "action": action,
                "actor": actor,
                "role": role,
                "detail": detail,
                "prev_hash": prev,
            }
            rec["hash"] = sha256_of({k: v for k, v in rec.items() if k != "hash"})
            self._rotate_if_needed()
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                f.flush()
            self._head = (rec["seq"], rec["hash"])
            return rec

    # -- 读 -----------------------------------------------------------------
    def iter_records(self):
        for seg in self.segments():
            try:
                with open(seg, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            yield json.loads(line)
                        except Exception:
                            continue
            except OSError:
                continue

    def count(self) -> int:
        return sum(1 for _ in self.iter_records())

    def tail(self, n: int = 50) -> list:
        buf = []
        for r in self.iter_records():
            buf.append(r)
            if len(buf) > n:
                buf.pop(0)
        return buf

    def verify_chain(self) -> dict:
        prev, expect_seq, count = "GENESIS", 1, 0
        for seg in self.segments():
            try:
                fh = open(seg, "r", encoding="utf-8")
            except OSError:
                continue
            with fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        r = json.loads(line)
                    except Exception:
                        return {"ok": False, "broken_at_seq": expect_seq,
                                "reason": "存在无法解析的日志行", "count": count}
                    expect = sha256_of({k: v for k, v in r.items() if k != "hash"})
                    if r.get("hash") != expect:
                        return {"ok": False, "broken_at_seq": r.get("seq"),
                                "reason": "内容与哈希不符（疑似被改写）", "count": count}
                    if r.get("prev_hash") != prev:
                        return {"ok": False, "broken_at_seq": r.get("seq"),
                                "reason": "prev_hash 断链", "count": count}
                    if int(r.get("seq", -1)) != expect_seq:
                        return {"ok": False, "broken_at_seq": r.get("seq"),
                                "reason": "seq 不连续（疑似丢行）", "count": count}
                    prev = r["hash"]
                    expect_seq += 1
                    count += 1
        return {"ok": True, "count": count}

    def query(self, keyword: str, limit: int = 2000) -> list:
        kw = keyword.strip().lower()
        out = []
        for r in self.iter_records():
            if not kw or kw in json.dumps(r, ensure_ascii=False).lower():
                out.append(r)
                if len(out) >= limit:
                    break
        return out

    def export_rows(self):
        for r in self.iter_records():
            yield r


DATA_LOG_H = HashChainLog(DATA_LOG)
OP_LOG_H = HashChainLog(OP_LOG)


def log_both(action, actor, role, detail):
    """每个人工动作同时落双轨日志（同一把锁，两轨都成功或都抛错）。"""
    with _IO_LOCK:
        DATA_LOG_H.append(action, actor, role, detail)
        OP_LOG_H.append(action, actor, role, detail)

# ---------------------------------------------------------------- 优化1：4 个 API 接口开关

APIS_FILE = os.path.join(HOME_DIR, "api_state.json")

def load_api_state():
    with _IO_LOCK:
        if os.path.exists(APIS_FILE):
            try:
                with open(APIS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
            except (OSError, ValueError):
                pass
    return {k: {"enabled": False, "approved_by": "", "ts": ""}
            for k in ["astm_ingest", "ocr_extract", "lis_writeback", "cloud_llm"]}

def save_api_state(st):
    with _IO_LOCK:
        _atomic_write_json(APIS_FILE, st)

API_META = {
    "astm_ingest":   ("ASTM 接入", "仪器 ASTM E1381/E1394 只读旁路接入"),
    "ocr_extract":   ("OCR 抽取", "乡镇场景拍照 OCR 结构化抽取"),
    "lis_writeback": ("LIS 回写", "向 LIS 回写结果（默认禁止）"),
    "cloud_llm":     ("云端大模型", "调用客户指定云端大模型"),
}


# ---------------------------------------------------------------- 登录失败锁定（V2.4）
LOGIN_STATE = os.path.join(HOME_DIR, "login_state.json")
LOGIN_MAX_FAILS = 5
LOGIN_LOCK_SEC = 300


def load_login_state() -> dict:
    with _IO_LOCK:
        if os.path.exists(LOGIN_STATE):
            try:
                with open(LOGIN_STATE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
            except (OSError, ValueError):
                pass
    return {}


def save_login_state(st: dict) -> None:
    with _IO_LOCK:
        _atomic_write_json(LOGIN_STATE, st)


# ---------------------------------------------------------------- 密钥落盘保护 + 备份恢复（V2.4）
_APIKEY_SALT = os.path.join(HOME_DIR, ".apikey.salt")


def _key_material() -> bytes:
    try:
        with open(_APIKEY_SALT, "rb") as f:
            data = f.read()
        if len(data) >= 16:
            return data
    except OSError:
        pass
    data = os.urandom(24)
    with open(_APIKEY_SALT, "wb") as f:
        f.write(data)
    return data


def _xor_bytes(raw: bytes) -> bytes:
    key = _key_material()
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))


def protect_secret(value: str) -> str:
    """API Key 落盘保护。

    诚实边界：这是**本地混淆**（随机盐 + XOR + Base64），能挡住“记事本打开就看到”，
    挡不住能同时读取 v2_data 与盐文件的本机攻击者。真正的密钥保护需要 OS 凭据库
    或 KMS，属上线前待办。
    """
    if not value:
        return ""
    return "enc:v1:" + base64.b64encode(_xor_bytes(value.encode("utf-8"))).decode("ascii")


def reveal_secret(value: str) -> str:
    if not value:
        return ""
    if not value.startswith("enc:v1:"):
        return value  # 兼容历史明文配置
    try:
        return _xor_bytes(base64.b64decode(value[7:])).decode("utf-8")
    except Exception:
        return ""


def backup_data(dest_zip: str) -> dict:
    """把 v2_data 整体打包（含日志、记录、证据包、账户）。"""
    count = 0
    with zipfile.ZipFile(dest_zip, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _dirs, files in os.walk(HOME_DIR):
            for name in files:
                p = os.path.join(root, name)
                try:
                    z.write(p, os.path.relpath(p, HOME_DIR))
                    count += 1
                except OSError:
                    continue
    return {"zip": dest_zip, "files": count, "size": os.path.getsize(dest_zip)}


def restore_data(src_zip: str) -> dict:
    """从备份恢复 v2_data（V2.5.1：整目录替换，不再是覆盖合并）。

    安全措施：
    1. 先把当前数据整体备份成 `v2_data.before_restore_<ts>.zip`；
    2. 解压到暂存目录校验通过后，再把现有数据整体移到 `v2_data.replaced_<ts>/`，
       最后把暂存内容移入数据目录 —— 任一步失败都不会留下半新半旧的数据；
    3. 恢复后必须重启程序（内存里的日志链缓存会失效）。

    为什么必须整目录替换（V2.5.1 修复）：
    旧实现直接 `extractall` 覆盖。恢复前若日志已发生分段轮转，归档段
    `data_log.jsonl.000001.jsonl` 不在备份里、也就不会被覆盖，恢复后它仍排在
    新日志之前，导致 `verify_chain()` 报「prev_hash 断链」、记录条数翻倍。
    审计方看到的是「日志被篡改」，实际只是一次恢复动作的副作用 —— 对一个以
    「哈希链可自证」为核心卖点的产品，这不能被接受。
    """
    home = os.path.abspath(HOME_DIR)
    base = os.path.abspath(BASE_DIR)
    if home == base:
        raise ValueError("数据目录与安装目录相同，拒绝执行恢复（可能覆盖程序文件）")
    safety = os.path.join(BASE_DIR, "v2_data.before_restore_" + ts_name() + ".zip")
    backup_data(safety)

    stamp = ts_name()
    stage = os.path.join(base, ".restore_stage_" + stamp)
    replaced = os.path.join(base, "v2_data.replaced_" + stamp)
    try:
        with zipfile.ZipFile(src_zip) as z:
            bad = [n for n in z.namelist()
                   if n.startswith(("/", "\\")) or ".." in n.replace("\\", "/").split("/")]
            if bad:
                raise ValueError("备份包包含非法路径，拒绝恢复：" + ", ".join(bad[:3]))
            z.extractall(stage)
        if not os.path.isdir(stage) or not os.listdir(stage):
            raise ValueError("备份包为空，拒绝恢复")
        # 现有数据整体移开（不是删除：出问题可原样移回）
        os.makedirs(replaced, exist_ok=True)
        moved = []
        for entry in os.listdir(home):
            try:
                shutil.move(os.path.join(home, entry), os.path.join(replaced, entry))
                moved.append(entry)
            except OSError:
                for e in moved:  # 回滚已移走的条目
                    try:
                        shutil.move(os.path.join(replaced, e), os.path.join(home, e))
                    except OSError:
                        pass
                raise
        # 暂存内容移入数据目录
        for entry in os.listdir(stage):
            shutil.move(os.path.join(stage, entry), os.path.join(home, entry))
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return {"restored_from": src_zip, "safety_backup": safety,
            "replaced_to": replaced, "replaced_count": len(moved)}

# ---------------------------------------------------------------- 优化4：记录与撤回/审核/删除

def load_records():
    with _IO_LOCK:
        if os.path.exists(RECORDS_FILE):
            try:
                with open(RECORDS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    return data
            except (OSError, ValueError):
                pass
    return []

def save_records(recs):
    with _IO_LOCK:
        _atomic_write_json(RECORDS_FILE, recs)

def next_record_no(existing=None):
    """记录编号发号器：以现有最大编号 +1，调用方须持锁读改写。"""
    recs = existing if existing is not None else load_records()
    nums = []
    for r in recs:
        rid = str(r.get("id", ""))
        if rid.startswith("REC-"):
            try:
                nums.append(int(rid.split("-", 1)[1]))
            except (IndexError, ValueError):
                continue
    return (max(nums) if nums else 0) + 1


def sink_records(records, source="api_bridge", actor=None, role=None):
    """统一落库：一条记录一次分配编号，全程持锁（V2.4 修复并发覆盖）。

    V2.5：写入 created_by / created_role / created_at。
    职责分离（审核人 ≠ 录入人）的前提是知道“谁录的”；旧实现只有 source（来源类型），
    凭证上无法证明检验与审核是两个人，也就无法回应 15189/9001 的分离要求。
    """
    if not records:
        return 0
    with _IO_LOCK:
        existing = load_records()
        no = next_record_no(existing)
        stamp = now_iso()
        added = 0
        for r in records:
            base = {k: v for k, v in r.items() if k not in ("id", "status", "source")}
            rec = {"id": f"REC-{no:04d}", "status": "待审核", "source": source}
            if actor:
                rec["created_by"] = actor
                rec["created_role"] = role or ""
                rec["created_at"] = stamp
            rec.update(base)
            existing.append(rec)
            no += 1
            added += 1
        save_records(existing)
        return added

def seed_records():
    recs = load_records()
    if not recs:
        recs = [
            {"id": "REC-0001", "type": "检验结果", "content": "WBC 12.3×10^9/L（偏高）", "status": "待审核"},
            {"id": "REC-0002", "type": "待关注列表", "content": "危急值预筛：GLU 24.6 mmol/L", "status": "待审核"},
            {"id": "REC-0003", "type": "脱敏记录", "content": "患者姓名已掩码：张*明", "status": "已审核"},
        ]
        save_records(recs)

# ---------------------------------------------------------------- 优化6/7：证据包自动生成

EVIDENCE_ROOT = os.path.join(HOME_DIR, "evidence_pack")
API_AUDIT = os.path.join(HOME_DIR, "api_audit.jsonl")   # 处置审计（脱敏/审核/熔断），由对接桥写入


def api_audit_chain() -> dict:
    """校验处置审计链；模块缺失或无日志时如实返回。"""
    if not os.path.exists(API_AUDIT):
        return {"ok": True, "count": 0, "note": "尚无处置审计（未运行 ASTM/OCR 链路）"}
    try:
        from labbridge_auditlog import AuditLog
        recs = AuditLog.load(API_AUDIT)
        return AuditLog.verify_chain(recs)
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def build_evidence_pack(actor: str, role: str) -> str:
    """生成全套证据包（V2.5：文件级哈希 + 处置审计 + 受控配置副本 + 操作日志摘录 + ZIP）。

    V2.5 相对 V2.4 的补强（针对二次复核 N-01/N-02）：
    - **受控配置副本**：随包交付 `critical_values.yaml`/`roles.yaml`/`access_map.csv`/
      `SHA256SUMS`。审计方要判断“危急值报告是否合规”，必须先知道当时生效的阈值；
      只给哈希不够——哈希只能证明文件没变，证明不了内容是什么。
    - **操作日志摘录**：出 seq/时间/动作/主体/角色/原因 + detail 键名，不出内部绝对路径。
      审计要的是“谁在何时做了什么”，尤其是 `config_resign` 这类改变签署主体的动作。
    - **manifest.config 段**：签署人、时间、原因、重签次数、被覆盖的原签署人、8 文件哈希。
      这一节是“配置是否被本地操作员替换过”的唯一书面凭据。
    - ZIP 改为递归收录，子目录（配置副本）不再丢失。

    诚实边界：摘录不含 detail 的值，故“改了哪个阈值”仍需对照配置副本与签署清单；
    摘录本身也受哈希保护，改动会被 MANIFEST.sha256 检出。
    """
    out = os.path.join(EVIDENCE_ROOT, "run_" + ts_name())
    os.makedirs(out, exist_ok=True)
    chain = DATA_LOG_H.verify_chain()
    ops_chain = OP_LOG_H.verify_chain()
    api_chain = api_audit_chain()
    cfg_chk = verify_config_integrity()

    # 受控配置副本：让包内能直接回答「当时的阈值/角色矩阵是什么」
    cfg_copy_dir = os.path.join(out, "受控配置_副本")
    os.makedirs(cfg_copy_dir, exist_ok=True)
    shipped_cfg = []
    for name in ("critical_values.yaml", "roles.yaml", "access_map.csv", "SHA256SUMS"):
        src = os.path.join(CONFIG_DIR_APP, name)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(cfg_copy_dir, name))
            shipped_cfg.append(name)

    # 操作日志摘录：只出“谁在何时做了什么”，不出内部路径与文件内容
    with open(os.path.join(out, "操作日志摘录_op_log.jsonl"), "w", encoding="utf-8") as f:
        for row in OP_LOG_H.export_rows():
            detail = row.get("detail") if isinstance(row.get("detail"), dict) else {}
            f.write(json.dumps({
                "seq": row.get("seq"),
                "ts": row.get("ts") or row.get("timestamp"),
                "action": row.get("action"),
                "actor": row.get("actor"),
                "role": row.get("role"),
                "detail_keys": sorted(detail.keys()),
                "reason": str(detail.get("reason") or ""),
                "superseded": str(detail.get("superseded") or ""),
            }, ensure_ascii=False) + "\n")

    def sig_block(title):
        return (f"\n\n---\n## 签名栏与日期签注栏\n\n"
                f"| 项目 | 内容 |\n|---|---|\n"
                f"| 文件名 | {title} |\n"
                f"| 生成时间 | {now_iso()} |\n"
                f"| 生成人（系统） | {actor}（{ROLE_NAMES.get(role, role)}） |\n"
                f"| 签名栏 | ______________________ |\n"
                f"| 日期签注栏 | ____年____月____日 |\n\n"
                f"> {DEMO_DISCLAIMER}\n")

    # 数据结果日志（流式写出，不再把全量日志读进内存）
    with open(os.path.join(out, "数据结果日志.jsonl"), "w", encoding="utf-8") as f:
        for r in DATA_LOG_H.export_rows():
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # 处置审计：脱敏 / 审核规则 / 熔断的真实证据（V2.4 新增）
    if os.path.exists(API_AUDIT):
        shutil.copy2(API_AUDIT, os.path.join(out, "处置审计_api_audit.jsonl"))

    # 人工审核记录（V2.5：加录入人列，用于证明检验-审核分离）
    with open(os.path.join(out, "人工审核记录.md"), "w", encoding="utf-8") as f:
        f.write("# 人工审核记录\n\n生成时间：" + now_iso() + "\n\n")
        f.write("| 编号 | 类型 | 状态 | 录入人 | 审核人 | 审核时间 | 审核意见 | 是否本人审核 |\n")
        f.write("|---|---|---|---|---|---|---|---|\n")
        for r in load_records():
            cb = str(r.get("created_by") or "-")
            ab = str(r.get("approved_by") or "-")
            same = ("是（破例）" if cb == ab and cb != "-" else ("否" if ab != "-" else "-"))
            f.write(f"| {r['id']} | {r['type']} | {r['status']} | {cb} | "
                    f"{ab} | {r.get('approved_at', '-')} | "
                    f"{r.get('approval_opinion', '-')} | {same} |\n")
        f.write("\n内容明细：\n")
        for r in load_records():
            f.write(f"\n- {r['id']}｜{r['content']}\n")
        f.write(sig_block("人工审核记录"))

    # 版本变更记录（V2.4：末行取真实 APP_VERSION，避免与实际版本不符）
    with open(os.path.join(out, "版本变更记录.md"), "w", encoding="utf-8") as f:
        f.write("# 版本变更记录\n\n| 版本 | 变更 |\n|---|---|\n")
        f.write("| V1 | 初版封包（13 模块） |\n")
        f.write("| V2 | 依据《V2优化项.txt》13 条重新封包 |\n")
        f.write("| V2.1 | 滑块开关、签字栏调整、PDCA 图谱汇总、人员权限收敛、检验数据结果页 |\n")
        f.write("| V2.2 | API 页精简、人员账户向下兼容、日志溯源详情+CSV、热力图响应 PDCA |\n")
        f.write("| V2.2.2 | 层级定稿 L1 工程师＞L2 主任＞L3 组长＞L4 检验员 |\n")
        f.write("| V2.3.0 | UI 简约现代化重设计（功能与逻辑不变） |\n")
        f.write("| V2.3.1 | 云端配置接口契约重写：参数校验、回填、连通测试、布局修复 |\n")
        f.write(f"| V{APP_VERSION} | 审批门接线、处置审计接入、并发写保护、PDCA 后台化、"
                "配置完整性校验、会话管理、记录检索、证据包自证、危急值提醒 |\n")
        f.write(f"| V{APP_VERSION} | 证据包加受控配置副本与操作日志摘录、记录加录入人与职责分离、"
                "重签须填原因并记重签次数、危急值改阈值判定、口令落盘混淆 |\n")
        f.write("| V2.5.1 | 恢复改为整目录替换：修复恢复后日志归档段残留导致哈希链误报断链 |\n")
        f.write("| V2.5.2 | NHANES 回放默认数据路径改为向上逐级搜索 公开数据/：修复交付封包布局下无参运行必然 FileNotFoundError |\n")
        f.write(f"\n生成时间：{now_iso()}\n")
        f.write(sig_block("版本变更记录"))

    # CAPA 整改记录
    with open(os.path.join(out, "CAPA_整改记录.md"), "w", encoding="utf-8") as f:
        f.write("# CAPA 整改记录\n\n| 问题 | 措施 | 状态 |\n|---|---|---|\n")
        f.write("| V2 优化项 1-13 | 逐条实现并自检 | 已落实（DEMO） |\n")
        f.write("| 2026-10-29 复核 G-01~G-14 | 审批门/审计接入/并发/PDCA/配置校验/会话/检索/证据自证/危急值 | 已整改（DEMO） |\n")
        f.write(sig_block("CAPA 整改记录"))

    # 不合适项标注
    with open(os.path.join(out, "DEMO声明与不合适项标注.md"), "w", encoding="utf-8") as f:
        f.write("# DEMO 声明与不合适项标注\n\n")
        f.write("以下输出项在 DEMO 阶段正常生成和记录，但**无法律法规意义**，只作为 DEMO 输出展示项：\n\n")
        for i, item in enumerate(NOT_SUITABLE_ITEMS, 1):
            f.write(f"{i}. 【不合适项标注】{item}\n")
        f.write("\n" + DEMO_DISCLAIMER + "\n")
        f.write(sig_block("DEMO声明与不合适项标注"))

    # 完整性清单：逐文件 SHA-256（V2.5：递归含子目录，配置副本也纳入校验）
    files = {}
    for root, _dirs, names in os.walk(out):
        for name in sorted(names):
            p = os.path.join(root, name)
            rel = os.path.relpath(p, out).replace("\\", "/")
            files[rel] = {"sha256": sha256_file(p), "size": os.path.getsize(p)}
    manifest = {
        "generated_at": now_iso(),
        "app_version": APP_VERSION,
        "actor": actor,
        "role": role,
        "chains": {
            "data_log": chain,
            "op_log_internal_only": ops_chain,
            "api_audit": api_chain,
        },
        "config": {
            "integrity": cfg_chk.get("status"),
            "signed_by": cfg_chk.get("signed_by"),
            "signed_at": cfg_chk.get("signed_at"),
            "reason": cfg_chk.get("reason"),
            "resign_count": cfg_chk.get("resign_count", 0),
            "superseded": cfg_chk.get("superseded", ""),
            "file_count": len(config_hashes()),
            "files": config_hashes(),
            "shipped_copy": shipped_cfg,
        },
        "files": files,
        "note": "MANIFEST.sha256 记录本文件的 SHA-256；被改动则与清单不符。",
    }
    man_path = os.path.join(out, "manifest.json")
    with open(man_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    with open(os.path.join(out, "MANIFEST.sha256"), "w", encoding="utf-8") as f:
        f.write(f"{sha256_file(man_path)}  manifest.json\n")

    # 同名 ZIP，整包交付（V2.5：递归，子目录如「受控配置_副本」不再丢失）
    zip_path = out + ".zip"
    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for root, _dirs, names in os.walk(out):
                for name in sorted(names):
                    p = os.path.join(root, name)
                    z.write(p, arcname=os.path.relpath(p, out))
    except OSError:
        zip_path = ""
    log_both("evidence_pack_export", actor, role,
             {"path": out, "zip": zip_path, "files": len(files),
              "data_log_ok": chain.get("ok"), "api_audit_ok": api_chain.get("ok"),
              "config_integrity": cfg_chk.get("status")})
    return out

# ---------------------------------------------------------------- 优化13：风险热力图数据

# 5 条通用风险（R-01~R-05）+ 3 条场景风险（R-06~R-08）+ 5 条敏感数据风险（SD-01~05）
HEATMAP_RISKS = [
    ("R-01", "通用", "AI幻觉生成虚假体系证据", 3, 3),
    ("R-02", "通用", "提示词注入越权/硬编码密钥", 2, 3),
    ("R-03", "通用", "敏感数据未分级管控", 2, 3),
    ("R-04", "通用", "知识库无版本管理", 3, 2),
    ("R-05", "通用", "业务逻辑硬绑定AI平台", 2, 2),
    ("R-06", "场景", "ASTM旁路被质疑干扰原系统", 3, 2),
    ("R-07", "场景", "乡镇OCR手写模糊准确率暴跌", 3, 2),
    ("R-08", "场景", "医院试用后无人付费签字", 3, 2),
    ("SD-01", "敏感数据", "患者身份信息明文外泄", 2, 4),
    ("SD-02", "敏感数据", "掩码规则被例外审批绕过", 2, 3),
    ("SD-03", "敏感数据", "操作日志外流导致二次泄露", 2, 3),
    ("SD-04", "敏感数据", "云端传输未加密/跨网违规", 2, 4),
    ("SD-05", "敏感数据", "危急值/结果日志被未授权导出", 1, 4),
]

# ---------------------------------------------------------------- GUI

# ================================================================ 设计系统（简约现代）
# 配色：中性色为主 + 单一强调色（蓝）；字体：无衬线；形态：扁平 / 轻阴影
FONT_FAMILY = "Microsoft YaHei UI"
C_BG        = "#F7F8FA"   # 窗口底色（浅灰）
C_SURFACE   = "#FFFFFF"   # 卡片 / 面板面
C_BORDER    = "#E5E7EB"   # 分隔线
C_LINE      = "#D0D5DD"   # 输入控件边框
C_TEXT      = "#1F2328"   # 主文字
C_MUTED     = "#6B7280"   # 次级文字
C_ACCENT    = "#2563EB"   # 唯一强调色
C_ACCENT_DK = "#1D4ED8"
C_ACCENT_SF = "#EFF6FF"   # 强调色浅底（选中行）
C_DANGER    = "#B42318"   # 仅用于破坏性操作的弱化提示色

def font(size=10, weight="normal"):
    return (FONT_FAMILY, size, weight)

def _resolve_font_family():
    global FONT_FAMILY
    try:
        import tkinter.font as tkfont
        fams = set(tkfont.families())
        for f in ("Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC",
                  "Segoe UI", "Helvetica", "Arial"):
            if f in fams:
                FONT_FAMILY = f
                return
    except Exception:
        pass

def apply_style(root=None):
    """统一应用简约现代风样式（幂等，可在任意窗口上调用）。"""
    _resolve_font_family()
    st = ttk.Style(root if root is not None else tk._default_root)
    try:
        st.theme_use("clam")   # clam 主题便于扁平化定制
    except tk.TclError:
        pass
    st.configure(".", background=C_BG, foreground=C_TEXT, font=font(10),
                 bordercolor=C_BORDER, lightcolor=C_BG, darkcolor=C_BG,
                 focuscolor=C_ACCENT, troughcolor=C_SURFACE)
    # 容器
    st.configure("TFrame", background=C_BG)
    st.configure("Card.TFrame", background=C_SURFACE, relief="solid", borderwidth=1,
                 bordercolor=C_BORDER)
    st.configure("Surface.TFrame", background=C_SURFACE)
    # 文字
    st.configure("TLabel", background=C_BG, foreground=C_TEXT, font=font(10))
    st.configure("Muted.TLabel", background=C_BG, foreground=C_MUTED)
    st.configure("Section.TLabel", background=C_BG, foreground=C_TEXT, font=font(11, "bold"))
    st.configure("Title.TLabel", background=C_BG, foreground=C_TEXT, font=font(16, "bold"))
    st.configure("Sub.TLabel", background=C_BG, foreground=C_MUTED, font=font(10))
    for name, fg, fnt in (("Card.TLabel", C_TEXT, font(10)),
                          ("Card.Muted.TLabel", C_MUTED, font(10)),
                          ("Card.Section.TLabel", C_TEXT, font(11, "bold"))):
        st.configure(name, background=C_SURFACE, foreground=fg, font=fnt)
    # 按钮：默认中性描边；主操作强调色；破坏性弱化红字
    st.configure("TButton", background=C_SURFACE, foreground=C_TEXT, font=font(10),
                 bordercolor=C_LINE, relief="flat", borderwidth=1, padding=(14, 7),
                 focuscolor=C_ACCENT)
    st.map("TButton", background=[("active", "#F3F4F6"), ("pressed", "#E9EBEF"),
                                  ("disabled", C_BG)],
           bordercolor=[("focus", C_ACCENT)])
    st.configure("Primary.TButton", background=C_ACCENT, foreground="#FFFFFF",
                 bordercolor=C_ACCENT, relief="flat", padding=(16, 8), font=font(10))
    st.map("Primary.TButton",
           background=[("active", C_ACCENT_DK), ("pressed", C_ACCENT_DK)])
    st.configure("Danger.TButton", background=C_SURFACE, foreground=C_DANGER,
                 bordercolor="#E7C9C5", relief="flat", padding=(14, 7), font=font(10))
    st.map("Danger.TButton", background=[("active", "#FEF3F2"), ("pressed", "#FCE9E7")])
    # 页签：扁平，选中态为强调色文字 + 卡片底
    st.configure("TNotebook", background=C_BG, borderwidth=0, tabmargins=(0, 2, 0, 0))
    st.configure("TNotebook.Tab", background=C_BG, foreground=C_MUTED,
                 padding=(18, 10), borderwidth=0, font=font(10))
    st.map("TNotebook.Tab", background=[("selected", C_SURFACE)],
           foreground=[("selected", C_ACCENT)],
           font=[("selected", font(10, "bold"))])
    # 输入控件
    for w in ("TEntry", "TCombobox"):
        st.configure(w, fieldbackground=C_SURFACE, background=C_SURFACE,
                     foreground=C_TEXT, bordercolor=C_LINE, relief="solid",
                     borderwidth=1, padding=(8, 6), arrowcolor=C_MUTED)
        st.map(w, bordercolor=[("focus", C_ACCENT)],
               arrowcolor=[("disabled", C_BORDER)])
    # 列表：扁平表头 + 轻条纹 + 强调色选中
    st.configure("Treeview", background=C_SURFACE, fieldbackground=C_SURFACE,
                 foreground=C_TEXT, bordercolor=C_BORDER, borderwidth=1,
                 relief="solid", rowheight=30, font=font(10))
    st.map("Treeview", background=[("selected", C_ACCENT_SF)],
           foreground=[("selected", C_TEXT)])
    st.configure("Treeview.Heading", background="#F3F4F6", foreground=C_MUTED,
                 font=font(10, "bold"), relief="flat", borderwidth=0, padding=(10, 8))
    st.map("Treeview.Heading", background=[("active", "#EDEFF2")])
    # 复选 / 分组 / 滚动条 / 分隔线
    st.configure("TCheckbutton", background=C_BG, foreground=C_TEXT,
                 indicatorcolor=C_SURFACE, indicatorbackground=C_SURFACE,
                 bordercolor=C_LINE, relief="flat", padding=(4, 4))
    st.map("TCheckbutton", indicatorcolor=[("selected", C_ACCENT), ("active", C_ACCENT)])
    st.configure("TLabelframe", background=C_SURFACE, bordercolor=C_BORDER,
                 borderwidth=1, relief="solid", padding=14)
    st.configure("TLabelframe.Label", background=C_BG, foreground=C_MUTED,
                 font=font(10, "bold"))
    st.configure("Vertical.TScrollbar", background=C_BG, troughcolor=C_BG,
                 bordercolor=C_BG, arrowcolor=C_MUTED, relief="flat", width=10)
    st.configure("Horizontal.TScrollbar", background=C_BG, troughcolor=C_BG,
                 bordercolor=C_BG, arrowcolor=C_MUTED, relief="flat", width=10)
    st.configure("TSeparator", background=C_BORDER)

# ---- 版式辅助：统一留白与层级，保证各页风格一致
def page_header(parent, title, subtitle=""):
    """页面统一标题区（标题 + 次级说明）。"""
    f = ttk.Frame(parent)
    f.pack(fill="x", pady=(0, 16))
    ttk.Label(f, text=title, style="Title.TLabel").pack(anchor="w")
    if subtitle:
        ttk.Label(f, text=subtitle, style="Sub.TLabel").pack(anchor="w", pady=(6, 0))
    return f

def card(parent, padding=16):
    """白色卡片容器（细边框，无重装饰）。"""
    return ttk.Frame(parent, style="Card.TFrame", padding=padding)

def action_bar(parent, pady=(12, 0)):
    """统一操作栏（按钮间距一致）。"""
    f = ttk.Frame(parent)
    f.pack(fill="x", pady=pady)
    return f

def text_widget(parent, height=16, size=10):
    """统一文本区（tk.Text 不响应 ttk 样式，故集中设置）。"""
    return tk.Text(parent, height=height, wrap="word", relief="solid", borderwidth=1,
                   highlightthickness=1, highlightbackground=C_BORDER,
                   highlightcolor=C_ACCENT, background=C_SURFACE, foreground=C_TEXT,
                   insertbackground=C_ACCENT, font=font(size), padx=12, pady=10,
                   spacing1=2, spacing3=2)

class LoginWindow(tk.Toplevel):
    def __init__(self, master, on_ok):
        super().__init__(master)
        self.on_ok = on_ok
        apply_style(self)
        self.title("登录 — " + APP_TITLE)
        self.geometry("400x330")
        self.configure(background=C_BG)
        self.resizable(False, False)
        # 注意：主窗口处于 withdraw 状态时，transient 登录窗在 Windows 上可能跟随隐藏，
        # 造成"打开 exe 无反应"。改用普通 Toplevel + 显示后 grab。
        self.attributes("-topmost", True)
        self.after(400, lambda: self.attributes("-topmost", False))
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.lift()
        self.focus_force()
        body = ttk.Frame(self, padding=32)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=APP_TITLE, style="Title.TLabel").pack(anchor="w")
        ttk.Label(body, text="请输入账户名与密码", style="Sub.TLabel").pack(anchor="w", pady=(6, 22))
        form = ttk.Frame(body); form.pack(fill="x")
        ttk.Label(form, text="账户名", style="Muted.TLabel").pack(anchor="w")
        self.user = ttk.Entry(form)
        self.user.pack(fill="x", pady=(6, 14), ipady=5)
        ttk.Label(form, text="密码", style="Muted.TLabel").pack(anchor="w")
        self.pwd = ttk.Entry(form, show="*")
        self.pwd.pack(fill="x", pady=(6, 24), ipady=5)
        ttk.Button(body, text="登 录", style="Primary.TButton",
                   command=self.try_login).pack(fill="x", ipady=3)
        ttk.Label(body, text="DEMO 账户：工程师 / 主任 / 组长 / 检验员（1111 / 3333 / 2222 / 4444）",
                  style="Sub.TLabel").pack(anchor="w", pady=(18, 0))
        self.bind("<Return>", lambda e: self.try_login())

    def try_login(self):
        u, p = self.user.get().strip(), self.pwd.get()
        st = load_login_state()
        info = st.get(u) or {"fails": 0, "lock_until": 0}
        now = time.time()
        if info.get("lock_until", 0) > now:
            left = int(info["lock_until"] - now) + 1
            messagebox.showerror("已锁定",
                                 f"该账户连续登录失败次数过多，已锁定。\n请 {left} 秒后再试。",
                                 parent=self)
            return
        for usr in load_users():
            if usr["username"] == u and usr["password"] == p:
                st.pop(u, None)
                save_login_state(st)
                log_both("login", u, usr["role"], {"level": usr["level"]})
                self.on_ok(usr)
                self.destroy()
                return
        info["fails"] = int(info.get("fails", 0)) + 1
        if info["fails"] >= LOGIN_MAX_FAILS:
            info["lock_until"] = now + LOGIN_LOCK_SEC
            info["fails"] = 0
            save_login_state({**st, u: info})
            log_both("login_locked", u or "(空)", "-",
                     {"reason": f"连续失败 {LOGIN_MAX_FAILS} 次，锁定 {LOGIN_LOCK_SEC} 秒"})
            messagebox.showerror("已锁定",
                                 f"连续失败 {LOGIN_MAX_FAILS} 次，账户已锁定 {LOGIN_LOCK_SEC // 60} 分钟。",
                                 parent=self)
            return
        save_login_state({**st, u: info})
        left = LOGIN_MAX_FAILS - info["fails"]
        log_both("login_failed", u or "(空)", "-", {"fails": info["fails"], "left": left})
        messagebox.showerror("登录失败",
                             f"账户名或密码错误（再错 {left} 次将锁定 {LOGIN_LOCK_SEC // 60} 分钟）",
                             parent=self)

    def _close(self):
        """关闭登录窗 = 退出程序（主窗口此刻仍隐藏，直接退出避免'无界面'假象）。"""
        self.master.destroy()

class App(tk.Tk):
    IDLE_LOCK_SEC = 600       # 10 分钟无操作自动锁定
    IDLE_TICK_MS = 15000

    def __init__(self):
        super().__init__()
        apply_style(self)
        self.configure(background=C_BG)
        self.title(APP_TITLE + "  v" + APP_VERSION)
        self.geometry("1080x720")
        self.minsize(980, 660)
        self.current_user = None
        self._last_activity = time.time()
        # V2.4：启动即校验受控配置（阈值/分级规则被改过必须让人知道）
        self.config_check = verify_config_integrity()
        if not self.config_check.get("ok"):
            log_both("config_integrity_fail", "system", "-", self.config_check)
        seed_records()
        self.api_state = load_api_state()

        self.topbar = ttk.Frame(self, padding=(18, 8, 18, 4))
        self.topbar.pack(fill="x")
        self.user_label = ttk.Label(self.topbar, text="未登录", style="Muted.TLabel")
        self.user_label.pack(side="left")
        self.config_badge = ttk.Label(self.topbar, text="", style="Muted.TLabel")
        self.config_badge.pack(side="left", padx=(16, 0))
        ttk.Button(self.topbar, text="注销 / 切换用户",
                   command=lambda: self.logout("manual")).pack(side="right")
        self._refresh_config_badge()

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True)
        self.tabs = {}
        for name, cls in [("主页", HomePanel), ("API 接口", ApiPanel),
                          ("人员管理", PeoplePanel), ("检验数据结果", ResultsPanel),
                          ("记录管理", RecordsPanel),
                          ("敏感信息查看", SensitivePanel), ("云端配置", CloudPanel),
                          ("日志溯源", TracePanel), ("风险热力图", HeatmapPanel),
                          ("PDCA 工具", PdcaPanel), ("证据包", EvidencePanel)]:
            frame = cls(self.nb, self)
            self.nb.add(frame, text=name)
            self.tabs[name] = frame
        # 空闲锁定：任何键鼠动作都刷新活跃时间
        for seq in ("<Any-KeyPress>", "<ButtonPress>", "<Motion>"):
            self.bind_all(seq, self._touch, add="+")
        self.after(self.IDLE_TICK_MS, self._idle_tick)
        # 启动时隐藏主窗口，登录成功后再显示，避免"登录后没有界面"的错觉
        self.withdraw()
        self.show_login()

    def _refresh_config_badge(self):
        st = self.config_check.get("status")
        text = {"signed": "受控配置：已签署 ✓",
                "unsigned": "受控配置：未签署（敏感链路已阻断）",
                "mismatch": "受控配置：已变更（敏感链路已阻断）",
                "unavailable": "受控配置：目录缺失"}.get(st, "受控配置：未知")
        self.config_badge.config(text=text)

    def _touch(self, event=None):
        self._last_activity = time.time()

    def _idle_tick(self):
        try:
            if self.current_user and time.time() - self._last_activity > self.IDLE_LOCK_SEC:
                self.logout("idle")
        finally:
            self.after(self.IDLE_TICK_MS, self._idle_tick)

    def show_login(self):
        LoginWindow(self, self.after_login)

    def logout(self, reason="manual"):
        u = self.current_user
        if u:
            log_both("session_lock" if reason == "idle" else "logout",
                     u["username"], u["role"], {"reason": reason})
        self.current_user = None
        self.user_label.config(text="未登录")
        self.title(APP_TITLE + "  v" + APP_VERSION)
        self.withdraw()
        self.show_login()

    def after_login(self, user):
        self.current_user = user
        self._last_activity = time.time()
        self.user_label.config(text=f"当前用户：{user['username']}（{ROLE_NAMES[user['role']]}，L{user['level']}）")
        self.title(f"{APP_TITLE}  v{APP_VERSION}  —  当前用户：{user['username']}（{ROLE_NAMES[user['role']]}，L{user['level']}）")
        # 显示主窗口并置顶聚焦
        self.deiconify()
        self.lift()
        self.attributes("-topmost", True)
        self.after(300, lambda: self.attributes("-topmost", False))
        self.focus_force()
        self.nb.select(0)  # 主页
        # V2.1：人员管理页锁定为本岗位职能（各级人员只能添加自己职能的账户）
        self.tabs["人员管理"].sync_role(user)
        # 登录后刷新一次配置状态（可能刚在主页完成签署）
        self.config_check = verify_config_integrity()
        self._refresh_config_badge()
        if not self.config_check.get("ok"):
            messagebox.showwarning(
                "受控配置校验未通过",
                "config/ 下的受控文件与签署清单不一致或尚未签署。\n"
                "敏感链路（ASTM/OCR/LIS/云端）已被阻断；请到「主页 → 受控配置」"
                "核对并重新签署。", parent=self)

    def require_login(self):
        if not self.current_user:
            messagebox.showwarning("未登录", "请先登录（右上角任意面板操作前须登录）")
            return False
        return True

# ---- 主页
class HomePanel(ttk.Frame):
    def __init__(self, nb, app):
        super().__init__(nb, padding=24)
        self.app = app
        page_header(self, "欢迎使用 " + APP_TITLE,
                    "当前为 DEMO 演示环境 · 零第三方依赖 · 数据本地留存")

        nav = card(self)
        nav.pack(fill="x")
        ttk.Label(nav, text="功能导航", style="Card.Section.TLabel").pack(anchor="w")
        ttk.Label(nav, text="请从上方页签选择：API 接口、人员管理、检验数据结果、记录管理、"
                            "敏感信息查看、云端配置、日志溯源、风险热力图、PDCA 工具、证据包。",
                  style="Card.Muted.TLabel", wraplength=900, justify="left").pack(anchor="w", pady=(8, 0))

        # V2.4：受控配置完整性
        cfg = card(self)
        cfg.pack(fill="x", pady=(14, 0))
        ttk.Label(cfg, text="受控配置完整性（config/ 共 %d 个受控文件）" % len(config_file_list()),
                  style="Card.Section.TLabel").pack(anchor="w")
        self.cfg_status = ttk.Label(cfg, text="", style="Card.Muted.TLabel",
                                    wraplength=900, justify="left")
        self.cfg_status.pack(anchor="w", pady=(8, 8))
        row = ttk.Frame(cfg, style="Surface.TFrame")
        row.pack(fill="x")
        ttk.Button(row, text="重新校验", command=self.refresh_status).pack(side="left")
        ttk.Button(row, text="按当前文件重新签署（需工程师密码）",
                   style="Primary.TButton", command=self.resign).pack(side="left", padx=(10, 0))
        ttk.Button(row, text="打开配置目录", command=self.open_cfg).pack(side="left", padx=(10, 0))

        # V2.4：数据备份 / 恢复
        bak = card(self)
        bak.pack(fill="x", pady=(14, 0))
        ttk.Label(bak, text="数据与备份", style="Card.Section.TLabel").pack(anchor="w")
        ttk.Label(bak, text="v2_data 内含日志、记录、账户与证据包。换机或清理前建议先备份。",
                  style="Card.Muted.TLabel", wraplength=900, justify="left").pack(anchor="w", pady=(8, 8))
        brow = ttk.Frame(bak, style="Surface.TFrame")
        brow.pack(fill="x")
        ttk.Button(brow, text="备份数据到 ZIP…", command=self.backup).pack(side="left")
        ttk.Button(brow, text="从 ZIP 恢复…", command=self.restore).pack(side="left", padx=(10, 0))
        ttk.Button(brow, text="打开数据目录", command=lambda: os.startfile(HOME_DIR)).pack(side="left", padx=(10, 0))
        self.refresh_status()

    def refresh_status(self):
        chk = verify_config_integrity()
        self.app.config_check = chk
        self.app._refresh_config_badge()
        st = chk.get("status")
        signed_by = str(chk.get("signed_by") or "—")
        signed_at = str(chk.get("signed_at") or "—")
        resign_n = int(chk.get("resign_count", 0) or 0)
        superseded = str(chk.get("superseded") or "")
        meta_line = f"签署人：{signed_by}｜时间：{signed_at}｜重签次数：{resign_n}"
        if superseded:
            meta_line += f"｜原签署人：{superseded}（已被覆盖）"
        if st == "signed":
            txt = (f"状态：已签署 ✓ 全部受控文件与签署清单一致。\n{meta_line}\n"
                   "说明：校验只能发现“文件被改动”，不能防止“改完再重签”；"
                   "重签须工程师密码 + 填写变更原因，均留痕。")
            if resign_n > 0:
                txt += ("\n提示：本清单已被重签过，若重签人不是发布方，"
                        "请在交付前说明变更依据。")
        elif st == "unsigned":
            txt = ("状态：**未签署**。config/ 尚未生成 SHA256SUMS，敏感链路已阻断。\n"
                   "处置：核对文件内容无误后，点「按当前文件重新签署」（需工程师密码）。")
        elif st == "unavailable":
            txt = "状态：**配置目录不存在**（" + CONFIG_DIR_APP + "），敏感链路不可用。"
        else:
            parts = []
            if chk.get("changed"):
                parts.append("内容被改：" + "、".join(chk["changed"]))
            if chk.get("missing"):
                parts.append("缺失：" + "、".join(chk["missing"]))
            if chk.get("extra"):
                parts.append("新增未登记：" + "、".join(chk["extra"]))
            txt = ("状态：**与签署清单不一致**，敏感链路已阻断。\n" + "；".join(parts) +
                   f"\n{meta_line}"
                   "\n处置：确认改动是受控变更后重新签署；否则从备份恢复 config/。")
        self.cfg_status.config(text=txt)

    def resign(self):
        if not self.app.require_login():
            return
        u = self.app.current_user
        if u["role"] != "engineer":
            messagebox.showerror("权限不足", "重新签署受控配置须工程师（L1）执行。", parent=self)
            return
        conf = _confirm_role_password(self, "重新签署受控配置", "engineer", "工程师",
                                      need_reason=True)
        if not conf:
            return
        reason = (conf.get("reason") or "").strip()
        prev = verify_config_integrity()
        prev_by = str(prev.get("signed_by") or "")
        sign_config_integrity(u["username"], reason=reason)
        log_both("config_resign", u["username"], u["role"],
                 {"dir": CONFIG_DIR_APP, "files": len(config_file_list()),
                  "reason": reason, "superseded": prev_by})
        self.refresh_status()
        warn = (f"\n\n注意：原签署人「{prev_by}」的签署已被覆盖，"
                f"清单头部会记录重签次数与原因。") if prev_by and prev_by != u["username"] else ""
        messagebox.showinfo("已签署", "已按当前文件内容生成 SHA256SUMS。\n"
                                     "请确认这些改动本身走了变更控制程序。" + warn, parent=self)

    def open_cfg(self):
        if os.path.isdir(CONFIG_DIR_APP):
            os.startfile(CONFIG_DIR_APP)
        else:
            messagebox.showwarning("不存在", "配置目录不存在：" + CONFIG_DIR_APP, parent=self)

    def backup(self):
        if not self.app.require_login():
            return
        path = filedialog.asksaveasfilename(
            title="备份 v2_data", defaultextension=".zip",
            initialfile="labbridge_backup_" + ts_name() + ".zip",
            filetypes=[("ZIP 备份", "*.zip")], parent=self)
        if not path:
            return
        try:
            r = backup_data(path)
        except OSError as e:
            messagebox.showerror("备份失败", str(e), parent=self)
            return
        log_both("data_backup", self.app.current_user["username"],
                 self.app.current_user["role"], r)
        messagebox.showinfo("备份完成",
                            f"已备份 {r['files']} 个文件（{r['size'] / 1024 / 1024:.1f} MB）到：\n{path}",
                            parent=self)

    def restore(self):
        if not self.app.require_login():
            return
        u = self.app.current_user
        if u["role"] != "engineer":
            messagebox.showerror("权限不足", "恢复数据须工程师（L1）执行。", parent=self)
            return
        path = filedialog.askopenfilename(title="选择备份 ZIP",
                                          filetypes=[("ZIP 备份", "*.zip")], parent=self)
        if not path:
            return
        if not messagebox.askyesno("确认恢复",
                                   "恢复将覆盖当前 v2_data（会先自动做一次安全备份）。\n"
                                   "恢复后需重启程序。是否继续？", parent=self):
            return
        try:
            r = restore_data(path)
        except Exception as e:
            messagebox.showerror("恢复失败", f"{type(e).__name__}: {e}", parent=self)
            return
        log_both("data_restore", u["username"], u["role"], r)
        messagebox.showinfo("恢复完成",
                            f"已从备份恢复。\n\n"
                            f"恢复前数据（含日志归档段）已整体移到：\n{r.get('replaced_to', '-')}\n"
                            f"安全备份：{r['safety_backup']}\n\n"
                            f"请重启程序后继续。确认无需回退后，可删除上述两处。",
                            parent=self)

# ---- 优化1（V2.1 改版）：现代滑块式开关控件
class Switch(tk.Canvas):
    """滑块式 toggle 开关（替代默认复选框样式）。"""

    def __init__(self, master, variable, command, width=54, height=26):
        super().__init__(master, width=width, height=height,
                         highlightthickness=0, bd=0, cursor="hand2")
        self.variable = variable
        self.command = command
        self.w, self.h = width, height
        self.bind("<Button-1>", self._click)
        self.variable.trace_add("write", lambda *a: self._draw())
        self._draw()

    def _pill(self, x0, y0, x1, y1, r, fill):
        self.create_rectangle(x0 + r, y0, x1 - r, y1, fill=fill, outline=fill)
        self.create_oval(x0, y0, x0 + 2 * r, y1, fill=fill, outline=fill)
        self.create_oval(x1 - 2 * r, y0, x1, y1, fill=fill, outline=fill)

    def _draw(self):
        self.delete("all")
        on = bool(self.variable.get())
        r = (self.h - 4) // 2
        self._pill(2, 2, self.w - 2, self.h - 2, r, C_ACCENT if on else "#DFE3E8")
        kx = self.w - 4 - r if on else 4 + r
        self.create_oval(kx - r, self.h // 2 - r, kx + r, self.h // 2 + r,
                         fill="#ffffff", outline="")
        self.create_text(10 if on else self.w - 10, self.h // 2,
                         text="开" if on else "关",
                         fill="#ffffff" if on else C_MUTED,
                         font=font(8), anchor="w" if on else "e")

    def _click(self, e=None):
        self.variable.set(not self.variable.get())
        if self.command:
            self.command()

# ---- 优化1：API 开关 + V3.1 对接配置区（开关是闸刀，配置区是接线端子）
API_CONFIG_FILE = os.path.join(HOME_DIR, "api_config.json")


def load_api_config():
    raw = {}
    if os.path.exists(API_CONFIG_FILE):
        try:
            with open(API_CONFIG_FILE, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, ValueError):
            raw = {}
    cfg = apib.merge_config(raw if isinstance(raw, dict) else None)
    llm = cfg.get("cloud_llm") or {}
    llm["api_key"] = reveal_secret(str(llm.get("api_key") or ""))
    cfg["cloud_llm"] = llm
    return cfg


def save_api_config(cfg):
    """落盘时把 api_key 换成保护形态；内存里的 cfg 仍是明文（供界面读回）。"""
    with _IO_LOCK:
        data = json.loads(json.dumps(cfg, ensure_ascii=False))
        llm = data.get("cloud_llm") or {}
        llm["api_key"] = protect_secret(str(llm.get("api_key") or ""))
        data["cloud_llm"] = llm
        _atomic_write_json(API_CONFIG_FILE, data)


class ApiPanel(ttk.Frame):
    def __init__(self, nb, app):
        super().__init__(nb, padding=24)
        self.app = app
        page_header(self, "API 接口",
                    "开关控制启停；「配置」展开对接参数并执行真实连通/接收动作，全部写入审计日志")
        self.cfg = load_api_config() if API_BRIDGE_OK else {}
        self.cfg_frames, self.cfg_open = {}, {}
        self.vars, self.status_labels = {}, {}
        self.rows = {}
        self._astm_thread = None
        self._astm_rcv = None
        for key, (name, desc) in API_META.items():
            row = card(self, padding=14)
            row.pack(fill="x", pady=(0, 10))
            left = ttk.Frame(row, style="Surface.TFrame")
            left.pack(side="left", fill="x", expand=True)
            head = ttk.Frame(left, style="Surface.TFrame")
            head.pack(fill="x")
            ttk.Label(head, text=name, style="Card.Section.TLabel").pack(side="left")
            var = tk.BooleanVar(value=self.app.api_state[key]["enabled"])
            Switch(head, var, lambda k=key, v=var: self.toggle(k, v)).pack(side="right", padx=(16, 4))
            ttk.Label(left, text=desc, style="Card.Muted.TLabel",
                      wraplength=780, justify="left").pack(anchor="w", pady=(4, 0))
            self.rows[key] = var
            # 配置区（默认收起）
            box = ttk.Frame(left, style="Surface.TFrame")
            self.cfg_frames[key] = box
            self.cfg_open[key] = False
            if API_BRIDGE_OK:
                self._build_cfg(key, box)
                ttk.Button(head, text="配置", width=6,
                           command=lambda k=key: self.toggle_cfg(k)).pack(side="right", padx=(0, 8))
            else:
                ttk.Label(left, text=f"对接层不可用：{API_BRIDGE_ERR}",
                          style="Card.Muted.TLabel").pack(anchor="w")

    CFG_FIELDS = {
        "astm_ingest": [
            ("mode", "接收模式", ("simulate(合成演示)", "replay(回放文件)", "tcp(TCP监听)", "serial(串口)")),
            ("codec", "字符集", ("UTF-8", "GBK", "Latin-1")),
        ],
    }

    def _build_cfg(self, key, box):
        """按接口构建配置字段与动作按钮。"""
        c = self.cfg[key]
        grid = ttk.Frame(box, style="Surface.TFrame")
        grid.pack(fill="x", pady=(8, 4))
        self.vars[key] = {}

        def add_row(label, widget):
            r = grid.grid_size()[1]
            ttk.Label(grid, text=label, style="Card.Muted.TLabel").grid(
                row=r, column=0, sticky="w", padx=(0, 8), pady=3)
            widget.grid(row=r, column=1, sticky="w", pady=3)
            return widget

        def entry(param, width=34, show=""):
            v = tk.StringVar(value=str(c.get(param, "")))
            self.vars[key][param] = v
            return add_row(param, ttk.Entry(grid, textvariable=v, width=width, show=show))

        def combo(param, values, width=18):
            v = tk.StringVar(value=str(c.get(param, values[0])))
            self.vars[key][param] = v
            return add_row(param, ttk.Combobox(grid, textvariable=v, values=values,
                                               width=width, state="readonly"))

        if key == "astm_ingest":
            combo("mode", ("simulate", "replay", "tcp", "serial"), 12)
            combo("codec", ("UTF-8", "GBK", "Latin-1"), 10)
            entry("file_path", 42)
            entry("tcp_host", 16); entry("tcp_port", 8)
            entry("serial_port", 10); entry("serial_baud", 8)
            entry("n_samples", 8)
            bar = ttk.Frame(grid, style="Surface.TFrame")
            grid.grid_columnconfigure(1, weight=1)
            add_row("动作", bar)
            ttk.Button(bar, text="启动接收", style="Primary.TButton",
                       command=lambda: self.run_astm()).pack(side="left", padx=(0, 8))
            ttk.Button(bar, text="停止监听", command=lambda: self.stop_astm()).pack(side="left", padx=(0, 8))
            ttk.Button(bar, text="浏览回放文件",
                       command=lambda: self.pick_file("file_path")).pack(side="left")
        elif key == "ocr_extract":
            entry("dir", 42)
            bar = ttk.Frame(grid, style="Surface.TFrame")
            add_row("动作", bar)
            ttk.Button(bar, text="扫描图片目录并受理", style="Primary.TButton",
                       command=lambda: self.run_ocr()).pack(side="left", padx=(0, 8))
            ttk.Button(bar, text="浏览目录",
                       command=lambda: self.pick_dir("dir")).pack(side="left")
        elif key == "lis_writeback":
            entry("host", 20); entry("port", 8)
            bar = ttk.Frame(grid, style="Surface.TFrame")
            add_row("动作", bar)
            ttk.Button(bar, text="连通性测试（回写默认禁止）", style="Primary.TButton",
                       command=lambda: self.run_lis()).pack(side="left")
        elif key == "cloud_llm":
            entry("base_url", 42); entry("api_key", 42, show="*"); entry("model", 20)
            bar = ttk.Frame(grid, style="Surface.TFrame")
            add_row("动作", bar)
            ttk.Button(bar, text="测试连接（仅发 1 token，不带患者数据）",
                       style="Primary.TButton",
                       command=lambda: self.run_llm()).pack(side="left")
        self.status_labels[key] = ttk.Label(box, text="", style="Card.Muted.TLabel",
                                            wraplength=760, justify="left")
        self.status_labels[key].pack(fill="x", pady=(2, 0))

    def toggle_cfg(self, key):
        self.cfg_open[key] = not self.cfg_open[key]
        if self.cfg_open[key]:
            self.cfg_frames[key].pack(fill="x", pady=(6, 0))
        else:
            self.cfg_frames[key].pack_forget()

    def _collect(self, key):
        cfg = self.cfg[key]
        for param, var in self.vars.get(key, {}).items():
            val = var.get()
            if param in ("tcp_port", "serial_baud", "n_samples"):
                try:
                    val = int(val)
                except ValueError:
                    pass
            cfg[param] = val.strip() if isinstance(val, str) else val
        save_api_config(self.cfg)
        return cfg

    def _set_status(self, key, text):
        def _do():
            self.status_labels[key].config(text=text)
        self.after(0, _do)

    def _require_bridge(self):
        if not self.app.require_login():
            return False
        if not API_BRIDGE_OK:
            messagebox.showerror("不可用", f"对接层加载失败：{API_BRIDGE_ERR}", parent=self)
            return False
        # V2.4：受控配置未通过校验时阻断敏感链路（阈值/分级规则可能已被改动）
        chk = verify_config_integrity()
        self.app.config_check = chk
        self.app._refresh_config_badge()
        if not chk.get("ok"):
            u = self.app.current_user
            messagebox.showerror(
                "受控配置未通过校验",
                f"状态：{chk.get('status')}\n"
                "受控配置（危急值阈值/分级规则等）与签署清单不一致或未签署，"
                "为避免按错误阈值处理数据，本次操作已阻断。\n\n"
                "请到「主页 → 受控配置完整性」核对并重新签署。", parent=self)
            log_both("config_integrity_block", u["username"], u["role"], chk)
            return False
        return True

    def pick_file(self, param):
        p = filedialog.askopenfilename(parent=self,
                                       filetypes=[("ASTM/文本", "*.astm *.txt *.log"), ("全部", "*.*")])
        if p:
            for k in self.vars:
                if param in self.vars[k]:
                    self.vars[k][param].set(p)

    def pick_dir(self, param):
        p = filedialog.askdirectory(parent=self)
        if p:
            for k in self.vars:
                if param in self.vars[k]:
                    self.vars[k][param].set(p)

    # -- 各接口真实动作（均在后台线程执行，UI 经 after 回写） ----------------

    def _sink_records(self, recs):
        """对接桥产出的统一记录 → GUI 记录库（records.json），加锁防并发覆盖。"""
        u = self.app.current_user or {}
        return sink_records(recs, source="api_bridge",
                            actor=u.get("username"), role=u.get("role"))

    def _audit_path(self):
        return os.path.join(HOME_DIR, "api_audit.jsonl")

    def run_astm(self):
        if not self._require_bridge():
            return
        cfg = self._collect("astm_ingest")
        u = self.app.current_user
        mode = cfg.get("mode", "simulate")
        if mode == "tcp" and self._astm_thread and self._astm_thread.is_alive():
            self._set_status("astm_ingest", "TCP 监听已在进行中；如需改参数请先「停止监听」")
            return
        self._set_status("astm_ingest", f"正在接收（{mode}）…")

        def work():
            try:
                if mode == "tcp":
                    from labbridge_astm import AstmReceiver
                    self._astm_rcv = AstmReceiver(mode="tcp", receive_timeout=float(cfg.get("timeout", 15)))
                    s = apib.astm_run(cfg, actor_id=u["username"], role=u["role"],
                                      records_sink=self._sink_records,
                                      audit_path=self._audit_path(), receiver=self._astm_rcv)
                else:
                    s = apib.astm_run(cfg, actor_id=u["username"], role=u["role"],
                                      records_sink=self._sink_records,
                                      audit_path=self._audit_path())
                log_both("api_astm_run", u["username"], u["role"],
                         {"mode": mode, "ok": s.get("ok"), "summary": {k: s.get(k) for k in
                          ("frames_ok", "results", "watchlist", "urgent", "ingested")}})
                if s.get("urgent"):
                    self._alert_critical(int(s.get("urgent") or 0), u)
                self._set_status("astm_ingest", "结果：" + json.dumps(
                    {k: s.get(k) for k in ("ok", "mode", "frames_ok", "frames_bad", "results",
                                           "watchlist", "urgent", "ingested", "leaks_blocked",
                                           "note", "error") if s.get(k) is not None},
                    ensure_ascii=False))
            except Exception as e:
                self._set_status("astm_ingest", f"失败：{type(e).__name__}: {e}")
        self._astm_thread = threading.Thread(target=work, daemon=True)
        self._astm_thread.start()

    def _alert_critical(self, count, user):
        """危急值强提醒（V2.4）：后台线程里不能直接弹窗，用 after 回主线程。"""
        def show():
            messagebox.showwarning(
                "危急值提醒",
                f"本次接收命中 {count} 条危急值/紧急项，已进入「检验数据结果」页（待审核）。\n\n"
                "请按危急值报告流程处置：\n"
                "· 核对标本与结果，排除仪器/录入错误；\n"
                "· 按制度时限通知临床并记录接收人；\n"
                "· 在「检验数据结果」页审核并填写意见。\n\n"
                "本 DEMO 不替代院内危急值报告制度。", parent=self)
            log_both("critical_acknowledged", user["username"], user["role"], {"count": count})
        self.after(0, show)

    def stop_astm(self):
        if self._astm_rcv is not None:
            self._astm_rcv.stop()
            self._set_status("astm_ingest", "已发送停止信号；监听线程将在当前连接超时后退出")

    def run_ocr(self):
        if not self._require_bridge():
            return
        cfg = self._collect("ocr_extract")
        u = self.app.current_user
        self._set_status("ocr_extract", "正在扫描…")

        def work():
            s = apib.ocr_scan_dir(cfg, actor_id=u["username"],
                                  records_sink=self._sink_records,
                                  audit_path=self._audit_path())
            log_both("api_ocr_run", u["username"], u["role"],
                     {"ok": s.get("ok"), "images": s.get("images"), "ingested": s.get("ingested")})
            self._set_status("ocr_extract", "结果：" + json.dumps(
                {k: s.get(k) for k in ("ok", "images", "available", "pending",
                                       "ingested", "note", "error") if s.get(k) is not None},
                ensure_ascii=False))
        threading.Thread(target=work, daemon=True).start()

    def run_lis(self):
        if not self._require_bridge():
            return
        cfg = self._collect("lis_writeback")
        u = self.app.current_user
        self._set_status("lis_writeback", "正在测试连通…")

        def work():
            s = apib.lis_ping(cfg)
            log_both("api_lis_ping", u["username"], u["role"], s)
            self._set_status("lis_writeback", "结果：" + json.dumps(s, ensure_ascii=False))
        threading.Thread(target=work, daemon=True).start()

    def run_llm(self):
        if not self._require_bridge():
            return
        cfg = self._collect("cloud_llm")
        u = self.app.current_user
        self._set_status("cloud_llm", "正在请求云端…")

        def work():
            s = apib.llm_ping(cfg)
            safe = {k: v for k, v in s.items() if k != "api_key"}
            log_both("api_llm_ping", u["username"], u["role"], safe)
            self._set_status("cloud_llm", "结果：" + json.dumps(safe, ensure_ascii=False))
        threading.Thread(target=work, daemon=True).start()

    def toggle(self, key, var):
        if not self.app.require_login():
            var.set(not var.get()); return
        u = self.app.current_user
        st = self.app.api_state[key]
        st["enabled"] = var.get()
        st["approved_by"] = u["username"]
        st["ts"] = now_iso()
        save_api_state(self.app.api_state)
        log_both("api_toggle", u["username"], u["role"],
                 {"api": key, "enabled": var.get()})

# ---- 优化3（V2.2.1 统一层级）：L1 可管理全部人员；L2 仅可管理 L2/L3/L4；以下类推
#      低层级不可反向管理高层级；主任(L1) 权限级别始终高于组长(L2)
class PeoplePanel(ttk.Frame):
    def __init__(self, nb, app):
        super().__init__(nb, padding=24)
        self.app = app
        page_header(self, "人员管理",
                    "按权限层级管理账户：Ln 可管理同级及以下，低层级不可反向管理高层级")
        box = card(self); box.pack(fill="x", pady=(0, 14))
        grid = ttk.Frame(box, style="Surface.TFrame"); grid.pack(fill="x")
        self.e_user = ttk.Entry(grid, width=16)
        self.e_role = ttk.Combobox(grid, values=list(ROLE_NAMES.values()), width=10,
                                   state="readonly")
        self.e_role.set("检验员")
        self.e_pwd = ttk.Entry(grid, width=14, show="*")
        for label, widget in [("账户名", self.e_user), ("角色", self.e_role), ("密码", self.e_pwd)]:
            cell = ttk.Frame(grid, style="Surface.TFrame")
            cell.pack(side="left", padx=(0, 16))
            ttk.Label(cell, text=label, style="Card.Muted.TLabel").pack(anchor="w")
            widget.pack(anchor="w", pady=(6, 0), ipady=4)
        cell = ttk.Frame(grid, style="Surface.TFrame"); cell.pack(side="left")
        ttk.Label(cell, text=" ", style="Card.Muted.TLabel").pack(anchor="w")
        ttk.Button(cell, text="添加人员", style="Primary.TButton",
                   command=self.add).pack(anchor="w", pady=(6, 0))
        self.tree = ttk.Treeview(self, columns=("user", "role", "level"),
                                 show="headings", height=12)
        for c, w in [("user", 200), ("role", 140), ("level", 100)]:
            self.tree.heading(c, text={"user": "账户名", "role": "角色", "level": "权限级别"}[c])
            self.tree.column(c, width=w)
        self.tree.pack(fill="both", expand=True)
        bar = action_bar(self)
        ttk.Button(bar, text="删除选中人员", style="Danger.TButton",
                   command=self.remove).pack(side="left")
        self.refresh()

    def _allowed_roles(self, user):
        """Ln 可管理同级及以下（L 数字更大）的职能账户；不可反向管理高层级。"""
        my = ROLE_LEVEL[user["role"]]
        return [k for k, r in ROLE_LEVEL.items() if r >= my]

    def sync_role(self, user):
        """登录后按层级规则放开可选角色：同级及以下。"""
        allowed = self._allowed_roles(user)
        self.e_role["values"] = [ROLE_NAMES[k] for k in allowed]
        self.e_role.set(ROLE_NAMES[allowed[0]])
        self.refresh()

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        cur = self.app.current_user["username"] if self.app.current_user else None
        for u in load_users():
            name = u["username"] + ("（当前登录）" if u["username"] == cur else "")
            self.tree.insert("", "end", iid=u["username"],
                             values=(name, ROLE_NAMES[u["role"]], "L%d" % u["level"]))

    def add(self):
        if not self.app.require_login(): return
        u = self.app.current_user
        name = self.e_user.get().strip()
        if not name or not self.e_pwd.get():
            messagebox.showwarning("输入不全", "请填写账户名和密码", parent=self); return
        role_cn = self.e_role.get()
        role = [k for k, v in ROLE_NAMES.items() if v == role_cn][0]
        if ROLE_LEVEL[role] < ROLE_LEVEL[u["role"]]:
            messagebox.showerror("权限不足",
                                 "层级管理规则：仅可添加同层级及以下（L 数字更大）的账户，"
                                 "低层级不可反向管理高层级账户",
                                 parent=self); return
        users = load_users()
        if any(x["username"] == name for x in users):
            messagebox.showerror("重复", "该账户名已存在", parent=self); return
        users.append({"username": name, "role": role, "password": self.e_pwd.get(),
                      "level": ROLE_LEVEL[role]})
        save_users(users)
        log_both("person_add", u["username"], u["role"], {"added": name, "role": role})
        self.refresh(); self.e_user.delete(0, "end"); self.e_pwd.delete(0, "end")

    def remove(self):
        if not self.app.require_login(): return
        u = self.app.current_user
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("未选择", "请先选中要删除的人员", parent=self); return
        name = sel[0]
        target = next((x for x in load_users() if x["username"] == name), None)
        if not target:
            messagebox.showerror("不存在", "该账户不存在", parent=self); return
        if name == u["username"]:
            messagebox.showwarning("不允许", "不能删除当前登录账户", parent=self); return
        if ROLE_LEVEL[target["role"]] < ROLE_LEVEL[u["role"]]:
            messagebox.showerror("权限不足",
                                 "层级管理规则：仅可删除同层级及以下（L 数字更大）的账户，"
                                 "低层级不可反向管理高层级账户",
                                 parent=self); return
        if not messagebox.askyesno("确认删除", f"确认删除人员「{name}」？", parent=self): return
        users = [x for x in load_users() if x["username"] != name]
        save_users(users)
        log_both("person_delete", u["username"], u["role"], {"deleted": name})
        self.refresh()

# ---- 优化4：记录 审核/撤回/删除
# ---------------------------------------------------------------- 记录动作（V2.4：审批门接线）
RECORD_STATES = ("待审核", "已审核", "已撤回", "已锁定")
APPROVER_ROLES = ("engineer", "director", "leader")   # L4 检验员不可审核


def _pseudo_id(*parts) -> str:
    """对象级审计用的伪ID：不落姓名/证件号，只留可回溯的短哈希。"""
    raw = "|".join(str(x) for x in parts if x)
    return "P-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8]


def _critical_thresholds() -> dict:
    """读受控危急值阈值（V2.5：GUI 判定与桥接侧共用同一份 config，不再各说各话）。"""
    p = os.path.join(CONFIG_DIR_APP, "critical_values.yaml")
    if not os.path.isfile(p):
        return {}
    try:
        from labbridge_config import load_yaml
        data = load_yaml(p) or {}
        vals = data.get("values") if isinstance(data, dict) else None
        return vals if isinstance(vals, dict) else {}
    except Exception:
        return {}


def judge_critical(item, value) -> str:
    """按受控阈值判定危急值，返回 "urgent" 或 ""。

    与 `labbridge_screen.r2_critical` 同口径（low/high 闭区间外即危急）。
    存在的意义：手工录入/OCR 人工录入不走审核引擎，旧实现只能靠文案里的
    “危急”二字判红，数值本身超阈值反而不会提醒。
    """
    th = _critical_thresholds().get(str(item or "").strip().upper())
    if not isinstance(th, dict):
        return ""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return ""
    lo, hi = th.get("low"), th.get("high")
    try:
        if lo is not None and v <= float(lo):
            return "urgent"
        if hi is not None and v >= float(hi):
            return "urgent"
    except (TypeError, ValueError):
        return ""
    return ""


def _is_critical(rec) -> bool:
    """危急值判定（V2.5：优先结构化 severity 字段，关键词仅作兜底）。

    旧实现只看 content 里有没有“危急/紧急/urgent/critical”字样：
    手工录入 "K 7.2 mmol/L" 不含这些字 → 不标红、不强提醒；文案一改也会静默失效。
    改为落库时写 severity 后，判定不再依赖措辞。
    """
    sev = str(rec.get("severity") or "").strip().lower()
    if sev in ("urgent", "critical", "high"):
        return True
    if sev in ("normal", "watch", "low", ""):
        if sev:
            return False
    text = str(rec.get("content", ""))
    return any(k in text for k in ("危急", "紧急", "urgent", "critical"))


def ask_approval(parent, rec):
    """审批四要素弹窗：动作计划 / 预期影响 / 风险提示 / 回滚方案 + 审核意见。"""
    win = tk.Toplevel(parent)
    win.title("审批确认（四要素）")
    win.grab_set()
    apply_style(win)
    win.geometry("760x520")
    win.configure(background=C_BG)
    body = ttk.Frame(win, padding=20)
    body.pack(fill="both", expand=True)
    ttk.Label(body, text=f"待审记录：{rec['id']}｜{rec['type']}", style="Section.TLabel").pack(anchor="w")
    ttk.Label(body, text=str(rec.get("content", ""))[:300], style="Muted.TLabel",
              wraplength=700, justify="left").pack(anchor="w", pady=(6, 10))
    box = text_widget(body, height=9)
    box.pack(fill="both", expand=True)
    for k, v in RecordActionsMixin.ELEMENTS.items():
        box.insert("end", f"【{k}】{v}\n\n")
    box.config(state="disabled")
    ttk.Label(body, text="审核意见（必填，至少 4 字）", style="Muted.TLabel").pack(anchor="w", pady=(10, 0))
    op = ttk.Entry(body)
    op.pack(fill="x", pady=(4, 10), ipady=5)
    op.focus()
    var = tk.BooleanVar(value=False)
    ttk.Checkbutton(body, text="我已逐条核对记录内容与规则命中项，并对以上四要素负责",
                    variable=var).pack(anchor="w")
    res = {}

    def ok():
        opinion = op.get().strip()
        if not var.get():
            messagebox.showwarning("未确认", "请先勾选确认项", parent=win)
            return
        if len(opinion) < 4:
            messagebox.showwarning("意见必填", "审核意见至少 4 个字", parent=win)
            return
        res["opinion"] = opinion
        res["elements"] = dict(RecordActionsMixin.ELEMENTS)
        win.destroy()

    bar = action_bar(body)
    ttk.Button(bar, text="确认审核", style="Primary.TButton", command=ok).pack(side="left", padx=(0, 8))
    ttk.Button(bar, text="取消", command=win.destroy).pack(side="left")
    parent.wait_window(win)
    return res or None


def _ask_director_confirm(parent, title, need_reason=True):
    """主任级密码确认（可附原因）。返回 {"reason": str} 或 None。"""
    return _confirm_role_password(parent, title, "director", "主任级别", need_reason)


def _confirm_role_password(parent, title, role, role_cn, need_reason=False):
    win = tk.Toplevel(parent)
    win.title(title)
    win.grab_set()
    apply_style(win)
    win.geometry("460x320")
    win.configure(background=C_BG)
    body = ttk.Frame(win, padding=22)
    body.pack(fill="both", expand=True)
    ttk.Label(body, text=title, style="Section.TLabel").pack(anchor="w")
    ttk.Label(body, text=f"{role_cn}密码", style="Muted.TLabel").pack(anchor="w", pady=(12, 0))
    e = ttk.Entry(body, show="*")
    e.pack(fill="x", pady=(4, 10), ipady=5)
    e.focus()
    reason = ttk.Entry(body)
    if need_reason:
        ttk.Label(body, text="操作原因（将写入审计日志）", style="Muted.TLabel").pack(anchor="w")
        reason.pack(fill="x", pady=(4, 10), ipady=5)
    res = {}

    def ok():
        pwd = e.get()
        if not any(x["role"] == role and x.get("password") == pwd for x in load_users()):
            messagebox.showerror("确认失败", f"{role_cn}密码不正确", parent=win)
            return
        if need_reason and len(reason.get().strip()) < 2:
            messagebox.showwarning("原因必填", "请填写操作原因", parent=win)
            return
        res["reason"] = reason.get().strip()
        win.destroy()

    bar = action_bar(body)
    ttk.Button(bar, text="确认", style="Primary.TButton", command=ok).pack(side="left", padx=(0, 8))
    ttk.Button(bar, text="取消", command=win.destroy).pack(side="left")
    win.bind("<Return>", lambda ev: ok())
    parent.wait_window(win)
    return res or None


class RecordActionsMixin:
    """审核 / 撤回 / 锁定 / 删除 / 导出的统一实现（V2.4）。

    相对旧实现补的四个缺口：
    1. 角色门禁：L4 检验员不能审核、撤回、删除（旧实现只校验“已登录”）；
    2. 审批四要素：审核前必须确认动作计划/预期影响/风险提示/回滚方案并填写意见；
    3. 状态机：待审核 → 已审核 → 已锁定；已审核撤回须主任密码；已锁定不可再改；
    4. 每次动作写双轨审计，detail 内含四要素、意见与原因。
    """

    ELEMENTS = {
        "动作计划": "将记录状态由「待审核」置为「已审核」，登记审核人与时间",
        "预期影响": "该结果进入后续交付/互认流程；不修改原始检验数值",
        "风险提示": "误审将使未复核结果被放行；规则命中项须逐条核对",
        "回滚方案": "由主任级密码确认后撤回至「待审核」，撤回动作留痕",
    }

    LOG_PREFIX = "record"
    CSV_HEAD = ["id", "type", "content", "severity", "created_by", "created_role", "created_at",
                "status", "approved_by", "approved_at",
                "approval_opinion", "recalled_by", "recalled_at", "locked_by", "locked_at"]

    # -- 数据 ---------------------------------------------------------------
    def _filtered(self):
        kw = self.kw.get().strip().lower()
        st = self.status_filter.get()
        out = []
        for r in load_records():
            if self.DATA_TYPES and r.get("type") not in self.DATA_TYPES:
                continue
            if st != "全部" and r.get("status") != st:
                continue
            if kw and kw not in json.dumps(r, ensure_ascii=False).lower():
                continue
            out.append(r)
        return out

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for r in self._filtered():
            tags = ("critical",) if _is_critical(r) else ()
            self.tree.insert("", "end", iid=r["id"], tags=tags,
                             values=(r["id"], r["type"], r["content"], r["status"]))
        if getattr(self, "SHOW_DETAIL", False):
            self.show_detail()

    def reset(self):
        self.kw.delete(0, "end")
        self.status_filter.set("全部")
        self.refresh()

    def _find(self, rid):
        return next((r for r in load_records() if r["id"] == rid), None)

    def _sel(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("未选择", f"请先选中一条{self.ITEM_NAME}", parent=self)
            return None
        return sel[0]

    def _deny_technician(self, action_cn):
        if self.app.current_user["role"] in APPROVER_ROLES:
            return False
        messagebox.showerror("权限不足",
                             f"检验员（L4）无{action_cn}权限。按文档 05 权限矩阵，"
                             f"审核与撤回须由 L1–L3 执行。", parent=self)
        return True

    # -- 动作 ---------------------------------------------------------------
    def approve(self):
        if not self.app.require_login():
            return
        if self._deny_technician("审核"):
            return
        rid = self._sel()
        if not rid:
            return
        rec = self._find(rid)
        if not rec:
            return
        if rec.get("status") == "已锁定":
            messagebox.showwarning("不可审核", "该记录已锁定，不能再变更状态。", parent=self)
            return
        if rec.get("status") == "已审核":
            messagebox.showinfo("无需重复", "该记录已是「已审核」状态。", parent=self)
            return
        u = self.app.current_user
        # 职责分离（V2.5）：录入人不得审核自己的记录（15189/9001 检验-审核分离）。
        # 极少数一人科室无法分离，主任可破例，但必须填理由并留痕。
        creator = str(rec.get("created_by") or "")
        if creator and creator == u["username"]:
            if u["role"] != "director":
                messagebox.showerror(
                    "违反职责分离",
                    f"该记录由「{creator}」录入，同一人不能审核自己的记录。\n\n"
                    "按文档 05 与 15189 的检验-审核分离要求，请换一个具备审核权限的账号。\n"
                    "（主任可破例自审，但须填写理由并留痕。）", parent=self)
                return
            conf = _confirm_role_password(self, "主任破例自审", "director", "主任级别",
                                          need_reason=True)
            if not conf:
                return
            log_both(self.LOG_PREFIX + "_selfapprove", u["username"], u["role"],
                     {"record": rid, "reason": (conf.get("reason") or ""),
                      "note": "主任破例自审（一人科室场景），已留痕"})
        payload = ask_approval(self, rec)
        if not payload:
            return
        with _IO_LOCK:
            recs = load_records()
            for r in recs:
                if r["id"] == rid:
                    r.update({"status": "已审核", "approved_by": u["username"],
                              "approved_at": now_iso(), "approval_opinion": payload["opinion"],
                              "approval_elements": payload["elements"]})
            save_records(recs)
        log_both(self.LOG_PREFIX + "_approve", u["username"], u["role"],
                 {"record": rid, "opinion": payload["opinion"],
                  "elements": payload["elements"], "from": rec.get("status"),
                  "created_by": creator or "-"})
        self.refresh()

    def recall(self):
        if not self.app.require_login():
            return
        if self._deny_technician("撤回"):
            return
        rid = self._sel()
        if not rid:
            return
        rec = self._find(rid)
        if not rec:
            return
        if rec.get("status") == "已锁定":
            messagebox.showwarning("不可撤回", "该记录已锁定，不可撤回。", parent=self)
            return
        if rec.get("status") != "已审核":
            messagebox.showwarning("状态不符", "只有「已审核」的记录可撤回。", parent=self)
            return
        conf = _ask_director_confirm(self, "撤回需主任级确认")
        if not conf:
            return
        u = self.app.current_user
        with _IO_LOCK:
            recs = load_records()
            for r in recs:
                if r["id"] == rid:
                    r.update({"status": "已撤回", "recalled_by": u["username"],
                              "recalled_at": now_iso(), "recall_reason": conf["reason"]})
            save_records(recs)
        log_both(self.LOG_PREFIX + "_recall", u["username"], u["role"],
                 {"record": rid, "reason": conf["reason"], "confirmed_by": "主任级密码"})
        self.refresh()

    def lock(self):
        if not self.app.require_login():
            return
        if self._deny_technician("锁定"):
            return
        rid = self._sel()
        if not rid:
            return
        rec = self._find(rid)
        if not rec:
            return
        if rec.get("status") != "已审核":
            messagebox.showwarning("状态不符", "只有「已审核」的记录可锁定。", parent=self)
            return
        if not messagebox.askyesno("确认锁定",
                                   "锁定后该记录不可再撤回或删除，仅可查看。是否继续？",
                                   parent=self):
            return
        u = self.app.current_user
        with _IO_LOCK:
            recs = load_records()
            for r in recs:
                if r["id"] == rid:
                    r.update({"status": "已锁定", "locked_by": u["username"],
                              "locked_at": now_iso()})
            save_records(recs)
        log_both(self.LOG_PREFIX + "_lock", u["username"], u["role"], {"record": rid})
        self.refresh()

    def delete(self):
        if not self.app.require_login():
            return
        if self._deny_technician("删除"):
            return
        rid = self._sel()
        if not rid:
            return
        rec = self._find(rid)
        if not rec:
            return
        if rec.get("status") == "已锁定":
            messagebox.showwarning("不可删除", "该记录已锁定，不可删除。", parent=self)
            return
        if rec.get("status") == "已审核":
            conf = _ask_director_confirm(self, "删除已审核记录需主任级确认")
            if not conf:
                return
        else:
            conf = {"reason": "未审核记录，操作人确认删除"}
            if not messagebox.askyesno("确认删除",
                                       f"确认删除 {rid}？（原记录仍留痕于审计日志）",
                                       parent=self):
                return
        u = self.app.current_user
        with _IO_LOCK:
            save_records([r for r in load_records() if r["id"] != rid])
        log_both(self.LOG_PREFIX + "_delete", u["username"], u["role"],
                 {"record": rid, "status": rec.get("status"), "reason": conf["reason"]})
        self.refresh()

    def export_csv(self):
        if not self.app.require_login():
            return
        rows = self._filtered()
        path = filedialog.asksaveasfilename(
            title="导出记录 CSV", defaultextension=".csv",
            initialfile=self.LOG_PREFIX + "_" + ts_name() + ".csv",
            filetypes=[("CSV 文件", "*.csv")], parent=self)
        if not path:
            return
        import csv
        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(self.CSV_HEAD)
            for r in rows:
                w.writerow([r.get(k, "") for k in self.CSV_HEAD])
        log_both(self.LOG_PREFIX + "_export_csv", self.app.current_user["username"],
                 self.app.current_user["role"], {"rows": len(rows), "to": path})
        messagebox.showinfo("导出完成", f"已导出 {len(rows)} 条到：\n{path}", parent=self)


class _RecordPanelBase(RecordActionsMixin, ttk.Frame):
    DATA_TYPES = None
    TITLE = "记录"
    SUBTITLE = ""
    SHOW_DETAIL = False
    ITEM_NAME = "记录"

    def __init__(self, nb, app):
        super().__init__(nb, padding=24)
        self.app = app
        page_header(self, self.TITLE, self.SUBTITLE)
        filt = action_bar(self, pady=(0, 12))
        ttk.Label(filt, text="搜索", style="Muted.TLabel").pack(side="left")
        self.kw = ttk.Entry(filt, width=30)
        self.kw.pack(side="left", padx=(6, 12), ipady=4)
        ttk.Label(filt, text="状态", style="Muted.TLabel").pack(side="left")
        self.status_filter = ttk.Combobox(filt, values=("全部",) + RECORD_STATES,
                                          width=8, state="readonly")
        self.status_filter.set("全部")
        self.status_filter.pack(side="left", padx=(6, 12))
        ttk.Button(filt, text="查询", style="Primary.TButton",
                   command=self.refresh).pack(side="left", padx=(0, 8))
        ttk.Button(filt, text="重置", command=self.reset).pack(side="left")
        self.tree = ttk.Treeview(self, columns=("id", "type", "content", "status"),
                                 show="headings", height=11)
        for c, w in [("id", 100), ("type", 120), ("content", 520), ("status", 100)]:
            self.tree.heading(c, text={"id": "编号", "type": "类型",
                                       "content": "内容", "status": "状态"}[c])
            self.tree.column(c, width=w)
        self.tree.tag_configure("critical", foreground=C_DANGER)
        self.tree.pack(fill="both", expand=True)
        if self.SHOW_DETAIL:
            self.detail = text_widget(self, height=5)
            self.detail.pack(fill="x", pady=(12, 0))
            self.tree.bind("<<TreeviewSelect>>", lambda e: self.show_detail())
        bar = self.action_bar = action_bar(self)
        ttk.Button(bar, text="审核通过", style="Primary.TButton",
                   command=self.approve).pack(side="left", padx=(0, 8))
        ttk.Button(bar, text="撤回", command=self.recall).pack(side="left", padx=(0, 8))
        ttk.Button(bar, text="锁定", command=self.lock).pack(side="left", padx=(0, 8))
        ttk.Button(bar, text="删除", style="Danger.TButton",
                   command=self.delete).pack(side="left", padx=(0, 8))
        ttk.Button(bar, text="导出 CSV", command=self.export_csv).pack(side="left", padx=(0, 8))
        ttk.Button(bar, text="刷新", command=self.refresh).pack(side="left")
        self.refresh()

    def show_detail(self):
        if not getattr(self, "detail", None):
            return
        self.detail.delete("1.0", "end")
        sel = self.tree.selection()
        if not sel:
            return
        r = self._find(sel[0])
        if not r:
            return
        self.detail.insert(
            "end",
            f"{r['id']}｜{r['type']}｜状态：{r['status']}\n"
            f"内容：{r['content']}\n"
            f"审核：{r.get('approved_by', '-')} {r.get('approved_at', '')}"
            f"　意见：{r.get('approval_opinion', '-')}\n"
            f"撤回：{r.get('recalled_by', '-')} {r.get('recalled_at', '')}"
            f"　原因：{r.get('recall_reason', '-')}"
            f"　锁定：{r.get('locked_by', '-')} {r.get('locked_at', '')}")


class RecordsPanel(_RecordPanelBase):
    TITLE = "记录管理"
    SUBTITLE = "审核（四要素）/ 撤回（主任确认）/ 锁定 / 删除（均为 L1–L3 权限）；操作写双轨审计"
    ITEM_NAME = "记录"
    LOG_PREFIX = "record"


class ResultsPanel(_RecordPanelBase):
    TITLE = "检验数据结果"
    SUBTITLE = "检验结果 / 待发列表：审核、撤回、锁定、删除；危急值行标红"
    DATA_TYPES = ("检验结果", "待发列表", "待关注列表")
    SHOW_DETAIL = True
    ITEM_NAME = "检验数据结果"
    LOG_PREFIX = "result"

    def __init__(self, nb, app):
        super().__init__(nb, app)
        ttk.Button(self.action_bar, text="导入回放结果…",
                   command=self.import_replay).pack(side="left", padx=(8, 0))
        ttk.Button(self.action_bar, text="人工录入…",
                   command=self.manual_entry).pack(side="left", padx=(8, 0))

    # -- G-11：回放结果导入（补上“能出报告但进不了台账”的断点） -------------
    def import_replay(self):
        if not self.app.require_login():
            return
        path = filedialog.askopenfilename(
            title="选择回放结果 JSON（nhanes_records.json 或 nhanes_replay_report.json）",
            filetypes=[("JSON 文件", "*.json"), ("全部", "*.*")], parent=self)
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            messagebox.showerror("读取失败", f"{type(e).__name__}: {e}", parent=self)
            return
        recs = data.get("records") if isinstance(data, dict) else data
        out = []
        if isinstance(recs, list) and recs:
            for r in recs[:500]:
                if not isinstance(r, dict):
                    continue
                item = r.get("test_item") or r.get("item") or r.get("项目")
                val = r.get("result_value", r.get("value"))
                if item is None and val is None:
                    continue
                out.append({"type": "检验结果",
                            "content": f"{item} {val}{r.get('unit', '')}"
                                       f"｜伪ID {r.get('patient_pseudo_id') or r.get('pseudo_id') or '-'}"
                                       f"｜来源 回放导入"})
        elif isinstance(data, dict) and isinstance(data.get("per_item"), dict):
            # 旧版报告只有汇总：如实体检为“摘要记录”，不伪造行级数据
            pi = data["per_item"]
            abnormal = sum(it.get("abnormal_low", 0) + it.get("abnormal_high", 0)
                           for it in pi.values() if isinstance(it, dict))
            total = sum(it.get("n", 0) for it in pi.values() if isinstance(it, dict))
            out.append({"type": "待发列表",
                        "content": f"回放摘要（旧版报告无行级记录）：{len(pi)} 个项目 / {total} 条结果 / "
                                   f"机器判据异常 {abnormal} 条｜来源 回放导入（仅为摘要）"})
        if not out:
            messagebox.showwarning("无可导入内容",
                                   "该文件既没有 records 列表，也不是可识别的回放报告。",
                                   parent=self)
            return
        u = self.app.current_user
        n = sink_records(out, source="replay_import",
                         actor=u["username"], role=u["role"])
        log_both("result_import_replay", u["username"], u["role"],
                 {"file": path, "rows": n, "has_line_level": isinstance(recs, list)})
        self.refresh()
        urgent = sum(1 for r in out if _is_critical(r))
        if urgent:
            messagebox.showwarning("危急值提醒",
                                   f"导入内容含 {urgent} 条危急/紧急项，请优先处置。", parent=self)
        messagebox.showinfo("导入完成", f"已导入 {n} 条到「检验数据结果」（待审核）。", parent=self)

    # -- G-11：人工录入（OCR 引擎缺失时的人工确认队列落地页） ----------------
    def manual_entry(self):
        if not self.app.require_login():
            return
        win = tk.Toplevel(self)
        win.title("人工录入检验结果")
        win.grab_set()
        apply_style(win)
        win.geometry("520x430")
        win.configure(background=C_BG)
        body = ttk.Frame(win, padding=22)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="人工录入（用于 OCR 未识别/待确认项目）",
                  style="Section.TLabel").pack(anchor="w")
        ttk.Label(body, text="录入内容视为人工判读结果，同样进入待审核状态并留痕。",
                  style="Muted.TLabel", wraplength=460, justify="left").pack(anchor="w", pady=(6, 12))
        fields = {}
        for label, key in [("检验项目（必填，如 WBC）", "item"), ("结果值（必填）", "value"),
                           ("单位（可空）", "unit"), ("患者伪ID（可空）", "pid"),
                           ("备注（可空）", "note")]:
            ttk.Label(body, text=label, style="Muted.TLabel").pack(anchor="w")
            e = ttk.Entry(body)
            e.pack(fill="x", pady=(4, 10), ipady=4)
            fields[key] = e
        fields["item"].focus()

        def ok():
            item = fields["item"].get().strip()
            value = fields["value"].get().strip()
            if not item or not value:
                messagebox.showwarning("必填", "检验项目与结果值不能为空", parent=win)
                return
            unit = fields["unit"].get().strip()
            pid = fields["pid"].get().strip() or "-"
            note = fields["note"].get().strip()
            content = f"{item} {value}{unit}｜伪ID {pid}｜来源 人工录入"
            if note:
                content += f"｜备注 {note}"
            sev = judge_critical(item, value)
            if sev:
                content += "｜危急值（超受控阈值，须立即处置）"
            rec = {"type": "检验结果", "content": content}
            if sev:
                rec["severity"] = sev
            u = self.app.current_user
            n = sink_records([rec],
                             source="ocr_manual", actor=u["username"], role=u["role"])
            with _IO_LOCK:
                recs = load_records()
                rid = recs[-1]["id"] if recs else "-"
            log_both("ocr_manual_entry", u["username"], u["role"],
                     {"record": rid, "item": item, "value": value, "unit": unit,
                      "pseudo_id": pid, "rows": n})
            win.destroy()
            self.refresh()
            if note and any(k in note for k in ("危急", "紧急")):
                messagebox.showwarning("危急值提醒", "备注含危急/紧急标记，请按危急值流程处置。",
                                       parent=self)

        bar = action_bar(body)
        ttk.Button(bar, text="保存并待审核", style="Primary.TButton",
                   command=ok).pack(side="left", padx=(0, 8))
        ttk.Button(bar, text="取消", command=win.destroy).pack(side="left")
        self.wait_window(win)


# ---- 优化10：敏感信息查看（主任级别密码确认）
class SensitivePanel(ttk.Frame):
    DEMO_DATA = [
        {"name": "张三丰", "phone": "13812345678", "idcard": "110101199001011234", "item": "GLU", "value": "24.6 mmol/L"},
        {"name": "李四", "phone": "13987654321", "idcard": "440101199202022345", "item": "WBC", "value": "12.3×10^9/L"},
        {"name": "王五", "phone": "13655557777", "idcard": "330101198803033456", "item": "Cr", "value": "156 μmol/L"},
    ]

    def __init__(self, nb, app):
        super().__init__(nb, padding=24)
        self.app = app
        page_header(self, "敏感信息查看",
                    "敏感·患者身份信息默认掩码显示，须主任级别密码确认后方可查看原文")
        bar = action_bar(self, pady=(0, 14))
        ttk.Button(bar, text="查看原文（需主任密码确认）", style="Primary.TButton",
                   command=self.view).pack(side="left")
        self.txt = text_widget(self, height=16)
        self.txt.pack(fill="both", expand=True)
        ttk.Label(self, text=SOP_RISK_NOTE_10, style="Muted.TLabel",
                  wraplength=920, justify="left").pack(fill="x", pady=(12, 0))
        self.show_masked()

    def show_masked(self):
        self.txt.delete("1.0", "end")
        self.txt.insert("end", "【默认掩码视图】\n\n")
        for r in self.DEMO_DATA:
            self.txt.insert("end", f"{r['name'][0]}*  {r['phone'][:3]}****{r['phone'][-4:]}"
                                   f"  身份证：**************{r['idcard'][-4:]}"
                                   f"  {r['item']} {r['value']}\n")

    def view(self):
        if not self.app.require_login(): return
        u = self.app.current_user
        pwd = _ask_password(self, "主任级别密码确认")
        if pwd is None:
            return
        users = load_users()
        directors = [x for x in users if x["role"] == "director"]
        if u["role"] == "director":
            # 主任本人：须输入主任级别密码；若主任只一人，可直接输入密码确认
            if not any(x["password"] == pwd for x in directors):
                messagebox.showerror("确认失败", "主任级别密码不正确", parent=self); return
            confirmer = u["username"] + "（本人，单主任场景）"
        else:
            # 工程师等其他角色：必须有主任级别密码确认
            if not any(x["password"] == pwd for x in directors):
                messagebox.showerror("确认失败",
                                     "须由主任级别密码确认后方可查看原文", parent=self); return
            confirmer = "主任级别密码确认"
        self.txt.delete("1.0", "end")
        self.txt.insert("end", f"【原文视图 · {confirmer} · {now_iso()}】\n\n")
        for r in self.DEMO_DATA:
            self.txt.insert("end", f"{r['name']}  {r['phone']}  {r['idcard']}  {r['item']} {r['value']}\n")
        # V2.4：对象级访问审计——只记伪ID与项目，不把姓名/证件号写进日志
        objs = [f"{_pseudo_id(r['name'], r['idcard'])}:{r['item']}" for r in self.DEMO_DATA]
        log_both("sensitive_view", u["username"], u["role"],
                 {"confirm": confirmer, "rows": len(self.DEMO_DATA), "objects": objs,
                  "scope": "患者身份信息原文"})

def _ask_password(parent, title):
    win = tk.Toplevel(parent); win.title(title); win.grab_set()
    apply_style(win)
    win.geometry("360x190")
    win.configure(background=C_BG)
    win.resizable(False, False)
    body = ttk.Frame(win, padding=24); body.pack(fill="both", expand=True)
    ttk.Label(body, text=title, style="Section.TLabel").pack(anchor="w")
    ttk.Label(body, text="请输入主任级别密码：", style="Muted.TLabel").pack(anchor="w", pady=(10, 0))
    e = ttk.Entry(body, show="*"); e.pack(fill="x", pady=(8, 0), ipady=5); e.focus()
    result = {"pwd": None}
    def ok():
        result["pwd"] = e.get(); win.destroy()
    def cancel():
        win.destroy()
    bar = action_bar(body)
    ttk.Button(bar, text="确认", style="Primary.TButton", command=ok).pack(side="left", padx=(0, 8))
    ttk.Button(bar, text="取消", command=cancel).pack(side="left")
    win.bind("<Return>", lambda ev: ok())
    parent.wait_window(win)
    return result["pwd"]

# ---- 优化11：云端配置
# 接口契约（cloud_config.json / CloudPanel 行为定义）：
#   配置对象 {"type": CLOUD_TYPES 之一, "addr": 主机名/IP/域名(可空), "port": 1-65535 整数}
#   保存：校验通过才落盘+写审计；校验失败不落盘、写 cloud_config_rejected 审计事件并提示原因
#   读取：打开页面回填；文件缺失→默认值；损坏/不合法→默认值+警告
#   测试连通：仅 TCP 握手（3s 超时），不发送任何数据（不含患者信息）
CLOUD_TYPES = ["医院内网", "局域网", "外网", "外置服务器"]


def validate_cloud_cfg(cfg):
    """校验云端配置对象。返回 (ok, error)。"""
    if not isinstance(cfg, dict):
        return False, "配置必须是 JSON 对象（{type, addr, port}）"
    if cfg.get("type") not in CLOUD_TYPES:
        return False, "云端类型须为 " + "/".join(CLOUD_TYPES) + " 之一"
    addr = str(cfg.get("addr") or "").strip()
    if addr:
        if len(addr) > 253 or not re.fullmatch(r"[A-Za-z0-9_\-\.]+", addr):
            return False, "地址格式不合法（仅支持主机名/IP/域名，不含协议头、路径与空格）"
    try:
        p = int(str(cfg.get("port")).strip())
    except (TypeError, ValueError):
        return False, "端口须为 1-65535 的整数"
    if not (1 <= p <= 65535):
        return False, "端口须在 1-65535 范围内（当前值不合法）"
    return True, ""


def cloud_config_path():
    return os.path.join(HOME_DIR, "cloud_config.json")


def load_cloud_config():
    """读取云端配置。返回 (cfg, warning)。文件缺失/损坏/不合法时回退默认值。"""
    default = {"type": "医院内网", "addr": "", "port": "8080"}
    try:
        with open(cloud_config_path(), encoding="utf-8") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        return dict(default), None
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
        return dict(default), "云端配置文件损坏或不可读，已回退默认值（" + str(e) + "）"
    ok, err = validate_cloud_cfg(cfg)
    if not ok:
        return dict(default), "已保存的云端配置不合法（" + err + "），已回退默认值"
    return cfg, None


def test_cloud_connect(addr, port, timeout=3.0):
    """TCP 连通性测试。返回 {ok, latency_ms, error}；只握手，不发送数据。"""
    t0 = time.time()
    try:
        with socket.create_connection((addr, int(port)), timeout=timeout):
            pass
        return {"ok": True, "latency_ms": round((time.time() - t0) * 1000), "error": ""}
    except OverflowError:
        return {"ok": False, "latency_ms": round((time.time() - t0) * 1000),
                "error": "端口号超出有效范围"}
    except OSError as e:
        return {"ok": False, "latency_ms": round((time.time() - t0) * 1000),
                "error": str(e) or e.__class__.__name__}


class CloudPanel(ttk.Frame):
    def __init__(self, nb, app):
        super().__init__(nb, padding=24)
        self.app = app
        page_header(self, "云端配置", "云端由客户自由指定，厂家不额外提供")
        box = card(self); box.pack(fill="x", pady=(0, 14))
        frm = ttk.Frame(box, style="Surface.TFrame"); frm.pack(fill="x", pady=4)
        self.cloud_type = ttk.Combobox(frm, values=CLOUD_TYPES, width=14, state="readonly")
        self.addr = ttk.Entry(frm, width=30)
        self.port = ttk.Entry(frm, width=10)
        for col, (label, widget) in enumerate(
                [("云端类型", self.cloud_type), ("地址", self.addr), ("端口", self.port)]):
            ttk.Label(frm, text=label, style="Card.Muted.TLabel").grid(
                row=0, column=col, sticky="w", padx=(0, 18), pady=(0, 6))
            widget.grid(row=1, column=col, sticky="w", padx=(0, 18), ipady=4)
        bar = ttk.Frame(frm, style="Surface.TFrame")
        bar.grid(row=2, column=0, columnspan=3, sticky="w", pady=(12, 2))
        ttk.Button(bar, text="保存配置", style="Primary.TButton",
                   command=self.save).pack(side="left")
        ttk.Button(bar, text="测试连通",
                   command=self.test).pack(side="left", padx=(10, 0))
        # 回填已保存配置（缺失/损坏时回退默认值并提示）
        cfg, warn = load_cloud_config()
        self.cloud_type.set(cfg.get("type") or "医院内网")
        self.addr.insert(0, str(cfg.get("addr") or ""))
        self.port.insert(0, str(cfg.get("port") or "8080"))
        self.txt = text_widget(self, height=8)
        self.txt.pack(fill="both", expand=True)
        self.txt.insert("end", (("⚠ " + warn + "\n\n") if warn else "") + CLOUD_RISK_NOTE)

    def _collect(self):
        return {"type": self.cloud_type.get(),
                "addr": self.addr.get().strip(),
                "port": self.port.get().strip()}

    def _show(self, text):
        self.txt.delete("1.0", "end"); self.txt.insert("end", text)

    def save(self):
        if not self.app.require_login(): return
        u = self.app.current_user
        cfg = self._collect()
        ok, err = validate_cloud_cfg(cfg)
        if not ok:
            self._show("保存失败：" + err + "\n\n" + CLOUD_RISK_NOTE)
            log_both("cloud_config_rejected", u["username"], u["role"], {"error": err, "cfg": cfg})
            return
        try:
            with open(cloud_config_path(), "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
        except OSError as e:
            self._show("保存失败：配置文件写入异常（" + str(e) + "）")
            log_both("cloud_config_write_error", u["username"], u["role"], {"error": str(e)})
            return
        self._show("已保存：" + json.dumps(cfg, ensure_ascii=False)
                   + "\n【端口示意】DEMO 搭配可能配置的端口为：" + (cfg["port"] or "8080")
                   + "（仅示意，不构成可用性承诺）。"
                   + "\n【成本提示】云端资源及相关成本由客户提供。\n\n" + CLOUD_RISK_NOTE)
        log_both("cloud_config", u["username"], u["role"], cfg)

    def test(self):
        if not self.app.require_login(): return
        u = self.app.current_user
        cfg = self._collect()
        ok, err = validate_cloud_cfg(cfg)
        if not ok:
            self._show("测试失败：" + err)
            return
        if not cfg["addr"]:
            self._show("测试失败：地址为空，无法发起连通测试。"
                       "（内网仅留档场景可不填地址、只保存配置）")
            return
        r = test_cloud_connect(cfg["addr"], cfg["port"])
        log_both("cloud_test", u["username"], u["role"],
                 {"addr": cfg["addr"], "port": cfg["port"], "ok": r["ok"]})
        if r["ok"]:
            self._show("连通正常：" + cfg["addr"] + ":" + cfg["port"]
                       + "  时延 " + str(r["latency_ms"]) + " ms"
                       + "（仅 TCP 握手，未发送任何数据，不含患者信息）")
        else:
            self._show("连通失败：" + cfg["addr"] + ":" + cfg["port"]
                       + "\n原因：" + r["error"]
                       + "\n排查建议：确认地址/端口正确、目标服务是否在线、防火墙是否放行。")

# ---- 优化12：日志溯源查询
class ApiAuditView:
    """处置审计（api_audit.jsonl）的只读视图，字段为模块 16 字段 Schema。"""

    CSV_HEAD = ["seq", "event_id", "timestamp", "actor_id", "actor_role", "action", "object",
                "data_class", "field_form", "policy_hit", "agent_version", "data_source",
                "human_involved", "result", "prev_hash", "hash"]

    def __init__(self, path: str):
        self.path = path
        self.internal = False

    def iter_records(self):
        if not os.path.exists(self.path):
            return iter(())
        try:
            from labbridge_auditlog import AuditLog
            return iter(AuditLog.load(self.path))
        except Exception:
            return iter(())

    def count(self) -> int:
        return sum(1 for _ in self.iter_records())

    def query(self, keyword: str, limit: int = 2000) -> list:
        kw = keyword.strip().lower()
        out = []
        for r in self.iter_records():
            if not kw or kw in json.dumps(r, ensure_ascii=False).lower():
                out.append(r)
                if len(out) >= limit:
                    break
        return out

    def verify_chain(self) -> dict:
        if not os.path.exists(self.path):
            return {"ok": True, "count": 0, "note": "尚无处置审计记录"}
        try:
            from labbridge_auditlog import AuditLog
            return AuditLog.verify_chain(AuditLog.load(self.path))
        except Exception as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}


class TracePanel(ttk.Frame):
    """日志溯源（V2.4）。

    三个日志源：
      数据结果日志  data_log.jsonl       对外可查可导出
      人员操作日志  op_log.jsonl         仅工程师可查可导，不作 9001 审计证据
      处置审计      api_audit.jsonl     脱敏/规则/熔断的真实处置证据（16 字段）
    """

    GUI_HEAD = ["seq", "event_id", "ts", "action", "actor", "role", "detail", "prev_hash", "hash"]

    def __init__(self, nb, app):
        super().__init__(nb, padding=24)
        self.app = app
        page_header(self, "日志溯源",
                    "用哈希值（任意片段）或 event_id 查询；人员操作日志仅工程师可查看/导出")
        bar = action_bar(self, pady=(0, 14))
        self.kw = ttk.Entry(bar, width=38)
        self.kw.pack(side="left", ipady=5)
        ttk.Button(bar, text="查询", style="Primary.TButton",
                   command=self.search).pack(side="left", padx=(10, 8))
        ttk.Button(bar, text="校验哈希链", command=self.verify).pack(side="left", padx=(0, 8))
        ttk.Button(bar, text="导出 CSV", command=self.export_csv).pack(side="left")
        srcbar = ttk.Frame(self); srcbar.pack(fill="x", pady=(0, 10))
        ttk.Label(srcbar, text="日志源", style="Muted.TLabel").pack(side="left")
        self.src = ttk.Combobox(srcbar, values=["数据结果日志", "人员操作日志", "处置审计"],
                                state="readonly", width=16)
        self.src.set("数据结果日志"); self.src.pack(side="left", padx=(10, 0))
        self.src.bind("<<ComboboxSelected>>", lambda e: self.refresh_hint())
        self.hint = ttk.Label(srcbar, text="", style="Muted.TLabel")
        self.hint.pack(side="left", padx=(12, 0))
        self.txt = text_widget(self, height=18)
        self.txt.pack(fill="both", expand=True)
        self.refresh_hint()

    def _log(self):
        name = self.src.get()
        if name.startswith("人员"):
            return OP_LOG_H
        if name.startswith("处置"):
            return ApiAuditView(API_AUDIT)
        return DATA_LOG_H

    def refresh_hint(self):
        log = self._log()
        try:
            n = log.count()
        except Exception:
            n = "?"
        self.hint.config(text=f"{os.path.basename(log.path)}｜共 {n} 条")

    def _check_op_perm(self, log):
        """人员操作日志：工程师权限（L1）内可查看/导出。"""
        if not getattr(log, "internal", False):
            return True
        u = self.app.current_user
        if u and u["role"] == "engineer":
            return True
        messagebox.showwarning("权限受限",
                               "人员操作日志需在「工程师」权限内查看与导出"
                               "（请以工程师账户 1111 登录后操作）", parent=self)
        return False

    def _render(self, recs, log):
        self.txt.delete("1.0", "end")
        self.txt.insert("end", f"命中 {len(recs)} 条（文件：{log.path}）：\n\n")
        for r in recs[-50:]:
            if "ts" in r:  # GUI 9 字段
                self.txt.insert("end",
                                f"—— seq={r['seq']}  event_id={r['event_id']}  {r['ts']} ——\n"
                                f"  动作: {r['action']}   操作人: {r['actor']}（{r['role']}）\n"
                                f"  具体内容: {json.dumps(r.get('detail', {}), ensure_ascii=False)}\n"
                                f"  prev_hash: {r['prev_hash']}\n  hash: {r['hash']}\n\n")
            else:  # 模块 16 字段
                self.txt.insert("end",
                                f"—— seq={r.get('seq')}  event_id={r.get('event_id')}  {r.get('timestamp')} ——\n"
                                f"  动作: {r.get('action')}   操作人: {r.get('actor_id')}（{r.get('actor_role')}）\n"
                                f"  对象: {r.get('object')}   分级: {r.get('data_class')}   形态: {r.get('field_form')}   "
                                f"命中策略: {r.get('policy_hit') or '-'}   结果: {r.get('result')}\n"
                                f"  来源: {r.get('data_source')}   人在回路: {r.get('human_involved')}\n"
                                f"  prev_hash: {r.get('prev_hash')}\n  hash: {r.get('hash')}\n\n")

    def search(self):
        if not self.app.require_login(): return
        log = self._log()
        if not self._check_op_perm(log):
            return
        self._render(log.query(self.kw.get()), log)

    def verify(self):
        if not self.app.require_login(): return
        log = self._log()
        if not self._check_op_perm(log):
            return
        res = log.verify_chain()
        name = self.src.get()
        self.txt.delete("1.0", "end")
        if res.get("ok"):
            msg = f"{name}哈希链校验：完整 ✓ 共 {res.get('count', 0)} 条\n"
        else:
            msg = (f"{name}哈希链校验：**损坏**\n"
                   f"  断点 seq = {res.get('broken_at_seq')}\n"
                   f"  原因：{res.get('reason') or res.get('error') or '校验失败'}\n"
                   "  处置：立即停止使用该日志举证，从备份恢复并排查写入方。\n")
        self.txt.insert("end", msg)

    def export_csv(self):
        if not self.app.require_login(): return
        log = self._log()
        if not self._check_op_perm(log):
            return
        head = ApiAuditView.CSV_HEAD if self.src.get().startswith("处置") else self.GUI_HEAD
        path = filedialog.asksaveasfilename(
            title="导出日志 CSV", defaultextension=".csv",
            initialfile=self.src.get() + "_" + ts_name() + ".csv",
            filetypes=[("CSV 文件", "*.csv")], parent=self)
        if not path:
            return
        import csv
        rows = 0
        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(head)
            for r in log.iter_records():
                vals = []
                for k in head:
                    v = r.get(k, "")
                    if isinstance(v, (dict, list)):
                        v = json.dumps(v, ensure_ascii=False)
                    vals.append(v)
                w.writerow(vals)
                rows += 1
        log_both("log_export_csv", self.app.current_user["username"],
                 self.app.current_user["role"],
                 {"source": os.path.basename(log.path), "rows": rows, "to": path})
        messagebox.showinfo("导出完成", f"已导出 {rows} 条到：\n{path}", parent=self)

# ---- 优化13：风险热力图
def pdca_risk_state():
    """V2.1.3：读取最近一次 PDCA 运行结果与 API 当前状态，返回热力图动态调整。
    返回 (info, deltas)；deltas: {rid: L增量}。"""
    deltas, notes = {}, []
    # 1) 最近一次 PDCA 运行结果
    runs_root = os.path.join(HOME_DIR, "pdca_runs")
    latest = None
    if os.path.isdir(runs_root):
        dirs = sorted(d for d in os.listdir(runs_root)
                      if os.path.isfile(os.path.join(runs_root, d, "05_PDCA工具运行结果.json")))
        if dirs:
            latest = dirs[-1]
    if latest:
        try:
            with open(os.path.join(runs_root, latest, "05_PDCA工具运行结果.json"),
                      encoding="utf-8") as f:
                res = json.load(f).get("results", [])
            bad = [r for r in res if r.get("status") != "PASS"]
            mask = any(r.get("id") == "spc" and r.get("output", {}).get("masking_detected")
                       for r in res)
            if bad:
                for rid in ("R-01", "R-04"):
                    deltas[rid] = deltas.get(rid, 0) + 1
                notes.append(f"PDCA 运行 {latest} 有 {len(bad)} 项非 PASS → R-01/R-04 可能性+1")
            if mask:
                deltas["R-03"] = deltas.get("R-03", 0) + 1
                notes.append("SPC 掩盖效应检出 → R-03 可能性+1")
        except Exception as e:
            notes.append(f"PDCA 结果读取失败：{e}")
    else:
        notes.append("尚无 PDCA 运行记录，热力图为基准状态")
    # 2) API 当前启用状态
    st = load_api_state()
    on = [k for k, v in st.items() if v.get("enabled")]
    if on:
        for rid in ("R-02", "SD-04"):
            deltas[rid] = deltas.get(rid, 0) + 1
        notes.append(f"API 已启用 {len(on)} 个 → R-02/SD-04 可能性+1")
    return ("；".join(notes) if notes else "热力图为基准状态"), deltas


class HeatmapPanel(ttk.Frame):
    CELL = 92
    def __init__(self, nb, app):
        super().__init__(nb, padding=24)
        self.app = app
        page_header(self, "风险热力图",
                    "L×C 九宫格（5 通用 + 3 场景 + 5 敏感数据），随每次 PDCA 运行结果响应变化")
        bar = action_bar(self, pady=(0, 14))
        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="显示热力图（可自由选择是否查看）",
                        variable=self.show_var, command=self.redraw).pack(side="left")
        body = ttk.Frame(self); body.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(body, width=520, bg=C_SURFACE, highlightthickness=1,
                                highlightbackground=C_BORDER)
        self.canvas.pack(side="left", fill="both", expand=True)
        # 图例：独立文本列表（逐行可分辨，不叠字）
        leg = ttk.Frame(body); leg.pack(side="right", fill="y", padx=(16, 0))
        self.leg_info = text_widget(leg, height=3, size=9)
        self.leg_info.pack(fill="x")
        self.leg = text_widget(leg, height=22, size=9)
        self.leg.pack(fill="both", expand=True, pady=(10, 0))
        for cat, col in [("通用", C_ACCENT), ("场景", "#0E7490"), ("敏感数据", C_DANGER)]:
            self.leg.tag_configure(cat, foreground=col)
        self.leg.tag_configure("head", font=font(9, "bold"), foreground=C_TEXT)
        self.leg.tag_configure("dim", foreground=C_MUTED)
        self.tip = ttk.Label(self, text="（将鼠标悬停在九宫格的风险编号上可查看全名）",
                             style="Muted.TLabel", wraplength=1000, justify="left")
        self.tip.pack(fill="x", pady=(12, 0))

    def _risks_dynamic(self):
        info, deltas = pdca_risk_state()
        out = []
        for rid, cat, desc, L, C in HEATMAP_RISKS:
            dL = deltas.get(rid, 0)
            out.append((rid, cat, desc, min(L + dL, 4), C, dL))
        return info, out

    def redraw(self):
        cv = self.canvas
        cv.delete("all")
        info, risks = self._risks_dynamic()
        # 图例顶部：PDCA 响应说明
        self.leg_info.delete("1.0", "end")
        self.leg_info.insert("end", "响应 PDCA：" + info)
        self.leg.delete("1.0", "end")
        if not self.show_var.get():
            cv.create_text(260, 240, text="（热力图默认隐藏，勾选上方按钮后显示）",
                           font=font(11), fill=C_MUTED)
            self.leg.insert("end", "（热力图隐藏中）")
            return
        ox, oy, cell = 70, 36, self.CELL
        # 风险等级配色：低饱和、同色系递进（保持中性克制）
        colors = {"低": "#EAF1E9", "中": "#FBF2DC", "高": "#F9E3E0", "极高": "#F2CBC6"}
        for L in range(4, 0, -1):
            for C in range(1, 5):
                R = L * C
                lvl = "极高" if R >= 9 else ("高" if R >= 6 else ("中" if R >= 3 else "低"))
                x = ox + (C - 1) * cell; y = oy + (4 - L) * cell
                cv.create_rectangle(x, y, x + cell, y + cell, fill=colors[lvl], outline=C_BORDER)
                cv.create_text(x + cell / 2, y + 12, text=f"L{L}×C{C}={R}",
                               font=font(9), fill=C_MUTED)
        cv.create_text(ox - 46, oy + 2 * cell, text="可能性 L→", angle=90, font=font(11))
        for L in range(1, 5):
            cv.create_text(ox - 24, oy + (4 - L) * cell + cell / 2, text=str(L),
                           font=font(11, "bold"))
        for C in range(1, 5):
            cv.create_text(ox + (C - 1) * cell + cell / 2, oy + 4 * cell + 16, text=str(C),
                           font=font(11, "bold"))
        cv.create_text(ox + 2 * cell, oy + 4 * cell + 36, text="后果 C→", font=font(11))
        # 风险点：同格内按行放置，只显示短编号（全名在右侧图例逐行列出，不叠字）
        grid = {}
        for rid, cat, desc, L, C, dL in risks:
            grid.setdefault((L, C), []).append((rid, cat, desc, dL))
        for (L, C), items in grid.items():
            x = ox + (C - 1) * cell; y = oy + (4 - L) * cell
            for i, (rid, cat, desc, dL) in enumerate(items):
                col = {"通用": C_ACCENT, "场景": "#0E7490", "敏感数据": C_DANGER}[cat]
                mark = "▲" if dL else ""
                t = cv.create_text(x + 8, y + 32 + i * 15, text=f"{mark}{rid}", anchor="w",
                                   font=font(9, "bold"), fill=col, tags=("risk", rid))
                cv.tag_bind(t, "<Enter>",
                            lambda e, d=(rid, cat, desc, dL, L, C): self._tip(d))
                cv.tag_bind(t, "<Leave>", lambda e: self.tip.config(
                    text="（将鼠标悬停在九宫格的风险编号上可查看全名）"))
        # 右侧清单：每行一条，分类着色，含 L×C 与调整标记
        self.leg.insert("end", "风险清单（随 PDCA 响应更新）\n", "head")
        for cat in ("通用", "场景", "敏感数据"):
            self.leg.insert("end", f"\n■ {cat}\n", (cat, "head"))
            for rid, c2, desc, L, C, dL in risks:
                if c2 != cat:
                    continue
                self.leg.insert("end", f"{rid}  {desc}\n", cat)
                self.leg.insert("end", f"     L{L}×C{C}" + ("　(▲ PDCA 响应 +1)" if dL else "") + "\n",
                                "dim" if not dL else "head")

    def _tip(self, d):
        rid, cat, desc, dL, L, C = d
        self.tip.config(text=f"{rid}（{cat}）L{L}×C{C}"
                             f"{'  ▲ 因 PDCA 结果可能性+1' if dL else ''}：{desc}")

# ---- 优化13：PDCA 工具（单独封包 + 每次展示分别记录不覆盖 + 可导出）
class PdcaPanel(ttk.Frame):
    def __init__(self, nb, app):
        super().__init__(nb, padding=24)
        self.app = app
        self.pdca_py = _find_pdca()
        page_header(self, "PDCA 工具",
                    "36 个质量管理工具，已单独封包为独立 EXE；每次运行输出独立目录，不覆盖历史")
        bar = action_bar(self, pady=(0, 14))
        self.btn_run = ttk.Button(bar, text="运行全量 PDCA 工具", style="Primary.TButton",
                                  command=self.run)
        self.btn_run.pack(side="left", padx=(0, 8))
        ttk.Button(bar, text="打开输出目录", command=self.open_out).pack(side="left")
        self.txt = text_widget(self, height=18)
        self.txt.pack(fill="both", expand=True)
        self.out_dir = None
        self._running = False

    def _pdca_cmd(self):
        """冻结环境调用单独封包的 PDCA EXE；开发环境调用 code/labbridge_pdca.py。"""
        if getattr(sys, "frozen", False):
            exe = os.path.join(os.path.dirname(sys.executable), "LabBridge_PDCA.exe")
            return [exe] if os.path.exists(exe) else None
        py = _find_pdca()
        return [sys.executable, py] if py else None

    def run(self):
        """V2.4：改到后台线程执行。旧实现在主线程同步跑，界面假死最长 10 分钟，
        超时抛出的 TimeoutExpired 在 windowed 模式下无人接（用户只看到“什么都没发生”）。"""
        if not self.app.require_login():
            return
        if self._running:
            messagebox.showinfo("正在运行", "上一轮 PDCA 工具尚未结束，请稍候。", parent=self)
            return
        cmd = self._pdca_cmd()
        if not cmd:
            messagebox.showerror("找不到",
                                 "未找到 PDCA 工具（请确认 LabBridge_PDCA.exe 与主程序同目录）",
                                 parent=self)
            return
        u = self.app.current_user
        # 各次生成的图表/报告分别记录，不覆盖（时间戳子目录）
        self.out_dir = os.path.join(HOME_DIR, "pdca_runs", ts_name())
        os.makedirs(self.out_dir, exist_ok=True)
        self._running = True
        self.btn_run.config(state="disabled", text="运行中…（3–10 分钟）")
        self.txt.delete("1.0", "end")
        self.txt.insert("end", f"已启动，输出目录（不覆盖历史）：{self.out_dir}\n"
                               "运行期间界面可继续操作，完成后结果会显示在这里。\n")

        def work():
            rc, out, err, errmsg = 0, "", "", ""
            try:
                proc = subprocess.run(cmd + ["--run", "-o", self.out_dir],
                                      capture_output=True, text=True, timeout=600)
                rc, out, err = proc.returncode, proc.stdout, proc.stderr
            except subprocess.TimeoutExpired:
                rc = -1
                errmsg = "运行超时（超过 600 秒），已中止。请检查 PDCA 工具是否卡住后重试。"
            except Exception as e:
                rc = -1
                errmsg = f"{type(e).__name__}: {e}"
            self.after(0, lambda: self._done(rc, out, err, errmsg, u))

        threading.Thread(target=work, daemon=True).start()

    def _done(self, rc, out, err, errmsg, u):
        self._running = False
        self.btn_run.config(state="normal", text="运行全量 PDCA 工具")
        self.txt.insert("end", (out or "")[-3000:])
        if errmsg:
            self.txt.insert("end", "\n[失败] " + errmsg + "\n")
            messagebox.showerror("PDCA 运行失败", errmsg, parent=self)
        elif rc != 0:
            self.txt.insert("end", "\n[stderr]\n" + (err or "")[-1500:])
            messagebox.showwarning("PDCA 运行异常",
                                   f"进程退出码 {rc}，详见页内输出。", parent=self)
        else:
            self.txt.insert("end", "\n完成。\n")
        log_both("pdca_run", u["username"], u["role"],
                 {"out": self.out_dir, "rc": rc, "error": errmsg})
        # PDCA 运行后风险热力图按结果响应变化
        try:
            self.app.tabs["风险热力图"].redraw()
        except Exception:
            pass

    def open_out(self):
        target = self.out_dir or os.path.join(HOME_DIR, "pdca_runs")
        os.makedirs(target, exist_ok=True)
        os.startfile(target)

def _find_pdca():
    cands = [
        os.path.join(BASE_DIR, "code", "labbridge_pdca.py"),
        os.path.join(BASE_DIR, "labbridge_pdca.py"),
        os.path.join(getattr(sys, "_MEIPASS", ""), "code", "labbridge_pdca.py"),
    ]
    for c in cands:
        if os.path.exists(c):
            return c
    return None

# ---- 优化6/7：证据包页
class EvidencePanel(ttk.Frame):
    def __init__(self, nb, app):
        super().__init__(nb, padding=24)
        self.app = app
        page_header(self, "证据包", "每次工具测试完成自动生成与导出全套证据包")
        bar = action_bar(self, pady=(0, 14))
        ttk.Button(bar, text="立即生成/导出证据包", style="Primary.TButton",
                   command=self.build).pack(side="left", padx=(0, 8))
        ttk.Button(bar, text="打开证据包目录", command=self.open_dir).pack(side="left")
        self.txt = text_widget(self, height=18)
        self.txt.pack(fill="both", expand=True)
        self.txt.insert("end", DEMO_DISCLAIMER + "\n\n不合适项标注（DEMO 输出展示项，无法律法规意义）：\n")
        for i, item in enumerate(NOT_SUITABLE_ITEMS, 1):
            self.txt.insert("end", f"  {i}. {item}\n")
        self.last = None

    def build(self):
        if not self.app.require_login(): return
        u = self.app.current_user
        self.last = build_evidence_pack(u["username"], u["role"])
        self.txt.delete("1.0", "end")
        self.txt.insert("end", f"证据包已生成：{self.last}\n\n包含：\n")
        for f in sorted(os.listdir(self.last)):
            self.txt.insert("end", f"  - {f}\n")
        self.txt.insert("end", "\n说明：工程师操作日志不对外直接输出（优化8），"
                               "仅保留痕迹与证据，不直接作为 9001 审计证据；"
                               "数据结果日志随包导出（优化9）。\n")
        self.txt.insert("end", "\n" + DEMO_DISCLAIMER + "\n")

    def open_dir(self):
        os.makedirs(EVIDENCE_ROOT, exist_ok=True)
        os.startfile(self.last or EVIDENCE_ROOT)

# ---------------------------------------------------------------- 入口

def _single_instance_guard():
    """单实例保护：已有一个实例在运行时，新启动的直接退出并提示。
    （此前多次启动的隐藏实例滞留后台，造成"再次打开 exe 无反应"。）"""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 47777))
        s.listen(1)
        return s
    except OSError:
        root = tk.Tk(); root.withdraw()
        messagebox.showinfo(APP_TITLE, "程序已在运行（可能在后台）。\n"
                            "请在任务栏或任务管理器中找到 LabBridgeV2，"
                            "或先结束旧进程再启动。")
        sys.exit(0)

def main():
    guard = _single_instance_guard()
    try:
        app = App()
        app.mainloop()
    except Exception:
        # EXE 为 windowed 模式，启动异常不会显示——落盘到 exe 旁便于排查
        import traceback
        err = os.path.join(BASE_DIR, "LabBridgeV2_error.log")
        with open(err, "a", encoding="utf-8") as f:
            f.write("\n[%s] 启动异常:\n%s\n" % (now_iso(), traceback.format_exc()))
        raise
    finally:
        guard.close()

if __name__ == "__main__":
    main()
