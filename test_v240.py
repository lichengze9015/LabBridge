# -*- coding: utf-8 -*-
"""V2.4 改造的无头验收测试（不启动 GUI）。

覆盖：并发写日志/记录、日志分段轮转、时区偏移、受控配置签署与篡改检测、
证据包文件级哈希与 ZIP、API Key 落盘保护、记录导入映射。
用法：python test_v240.py
"""
import json
import os
import shutil
import sys
import tempfile
import threading

sys.argv = ["test_v240"]
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("v2app", os.path.join(HERE, "labbridge_v2_app.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

TMP = tempfile.mkdtemp(prefix="lb_v240_")
# 安装目录（BASE_DIR）与数据目录必须是两个不同位置：restore_data 会在 BASE_DIR
# 放安全备份与「已移出」目录，且拒绝在 home==base 时执行（防覆盖程序文件）。
BASE_TMP = tempfile.mkdtemp(prefix="lb_v240_base_")
OK = []


def check(name, cond, extra=""):
    OK.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (("  " + extra) if extra else ""))


# ---- 指向临时目录 ---------------------------------------------------------
m.HOME_DIR = TMP
m.BASE_DIR = BASE_TMP
m.USERS_FILE = os.path.join(TMP, "users.json")
m.RECORDS_FILE = os.path.join(TMP, "records.json")
m.API_CONFIG_FILE = os.path.join(TMP, "api_config.json")
m.EVIDENCE_ROOT = os.path.join(TMP, "evidence")
m.API_AUDIT = os.path.join(TMP, "api_audit.jsonl")
m.LOGIN_STATE = os.path.join(TMP, "login_state.json")
m.DATA_LOG_H = m.HashChainLog(os.path.join(TMP, "data_log.jsonl"))
m.OP_LOG_H = m.HashChainLog(os.path.join(TMP, "op_log.jsonl"))
os.makedirs(os.path.join(TMP, "config"))
for f in os.listdir(os.path.join(HERE, "config")):
    # 不拷签署清单：测试必须从「未签署」这个确定的初始态开始，
    # 否则结果取决于真实 config 目录当前是否已签署，不可重复。
    if f == "SHA256SUMS":
        continue
    if os.path.isfile(os.path.join(HERE, "config", f)):
        shutil.copy2(os.path.join(HERE, "config", f), os.path.join(TMP, "config", f))
m.CONFIG_DIR_APP = os.path.join(TMP, "config")
m.CONFIG_MANIFEST = os.path.join(m.CONFIG_DIR_APP, "SHA256SUMS")


# ---- [1] 时区 -------------------------------------------------------------
ts = m.now_iso()
check("[1] 时间戳带时区偏移", len(ts) > 19 and (ts[-6] in "+-" or ts[-3] == ":"), ts)


# ---- [2] 日志并发写 -------------------------------------------------------
log = m.DATA_LOG_H


def worker(i):
    for j in range(50):
        log.append("concurrent", f"u{i}", "engineer", {"i": i, "j": j})


ths = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
[t.start() for t in ths]
[t.join() for t in ths]
res = log.verify_chain()
check("[2] 8 线程×50 条并发写后链完整", res.get("ok") and res.get("count") == 400, json.dumps(res, ensure_ascii=False))


# ---- [3] 分段轮转 ---------------------------------------------------------
m.DATA_LOG_H = m.HashChainLog(os.path.join(TMP, "rot", "data_log.jsonl"))
os.makedirs(os.path.join(TMP, "rot"), exist_ok=True)
rlog = m.DATA_LOG_H
rlog.ROTATE_BYTES = 4096
for i in range(120):
    rlog.append("rot", "u", "engineer", {"pad": "x" * 200, "i": i})
rres = rlog.verify_chain()
check("[3] 轮转后跨段链完整", rres.get("ok") and rres.get("count") == 120, json.dumps(rres, ensure_ascii=False))
check("[3b] 已产生归档分段", len(rlog._archive_files()) >= 1, f"segments={len(rlog.segments())}")


# ---- [4] 记录并发落库 -----------------------------------------------------
def sink_worker(i):
    for j in range(30):
        m.sink_records([{"type": "检验结果", "content": f"item{i}-{j} 1.0mmol/L"}], source="test")


ths = [threading.Thread(target=sink_worker, args=(i,)) for i in range(6)]
[t.start() for t in ths]
[t.join() for t in ths]
recs = m.load_records()
ids = [r["id"] for r in recs]
check("[4] 6 线程×30 条无丢失", len(recs) == 180, f"实际 {len(recs)}")
check("[4b] 编号唯一", len(set(ids)) == len(ids), f"唯一 {len(set(ids))}/{len(ids)}")
check("[4c] 编号连续", sorted(int(x.split('-')[1]) for x in ids) == list(range(1, 181)))


# ---- [5] 受控配置签署与篡改检测 -------------------------------------------
check("[5] 未签署状态", m.verify_config_integrity()["status"] == "unsigned")
m.sign_config_integrity("tester")
check("[5b] 签署后一致", m.verify_config_integrity()["ok"] is True)
p = os.path.join(m.CONFIG_DIR_APP, "critical_values.yaml")
before = open(p, encoding="utf-8").read()
open(p, "w", encoding="utf-8").write(before.replace("6.5", "60.5", 1))
chk = m.verify_config_integrity()
check("[5c] 篡改被检出", (not chk["ok"]) and "critical_values.yaml" in chk["changed"],
      json.dumps({k: chk[k] for k in ("status", "changed")}, ensure_ascii=False))
open(p, "w", encoding="utf-8").write(before)
m.sign_config_integrity("tester")


# ---- [6] 处置审计 + 证据包 ------------------------------------------------
with open(m.API_AUDIT, "w", encoding="utf-8") as f:
    f.write(json.dumps({"event_id": "e1", "seq": 1, "timestamp": m.now_iso(),
                        "actor_id": "tech01", "actor_role": "technician",
                        "action": "deid", "object": "result:1", "data_class": "sensitive",
                        "field_form": "raw", "policy_hit": "mask_phone",
                        "agent_version": "v3", "data_source": "astm_simulate",
                        "human_involved": False, "result": "ok",
                        "prev_hash": "GENESIS", "hash": "X"}, ensure_ascii=False) + "\n")
m.log_both("ui_action", "工程师", "engineer", {"x": 1})
out = m.build_evidence_pack("工程师", "engineer")
files = sorted(os.listdir(out))
man = json.load(open(os.path.join(out, "manifest.json"), encoding="utf-8"))
check("[6] 证据包含处置审计", "处置审计_api_audit.jsonl" in files, str(files))
check("[6b] manifest 逐文件哈希", isinstance(man.get("files"), dict) and
      all("sha256" in v for v in man["files"].values()), f"{len(man.get('files', {}))} 个文件")
check("[6c] MANIFEST.sha256 与 manifest 一致",
      open(os.path.join(out, "MANIFEST.sha256"), encoding="utf-8").read().split()[0]
      == m.sha256_file(os.path.join(out, "manifest.json")))
check("[6d] 版本记录含真实版本", m.APP_VERSION in open(os.path.join(out, "版本变更记录.md"), encoding="utf-8").read(),
      m.APP_VERSION)
check("[6e] 同目录 ZIP 已生成", os.path.exists(out + ".zip") and os.path.getsize(out + ".zip") > 0)


# ---- [7] 密钥落盘保护 -----------------------------------------------------
m.save_api_config({"cloud_llm": {"base_url": "https://x", "api_key": "sk-secret-123", "model": "m"},
                   "astm_ingest": {"mode": "simulate"}})
raw = open(m.API_CONFIG_FILE, encoding="utf-8").read()
check("[7] 落盘不含明文密钥", "sk-secret-123" not in raw and "enc:v1:" in raw)
cfg = m.load_api_config()
check("[7b] 读回为明文", cfg["cloud_llm"]["api_key"] == "sk-secret-123", cfg["cloud_llm"]["api_key"])


# ---- [8] 登录失败计数 -----------------------------------------------------
st = {**m.load_login_state(), "检验员": {"fails": 3, "lock_until": 0}}
m.save_login_state(st)
check("[8] 登录失败状态可持久化", m.load_login_state()["检验员"]["fails"] == 3)


# ---- [9] 备份 / 恢复 -----------------------------------------------------
z = os.path.join(TMP, "backup.zip")
r = m.backup_data(z)
check("[9] 备份生成", os.path.exists(z) and r["files"] > 0, json.dumps(r, ensure_ascii=False))


# ---- [10] 证据包审计充分性（N-01）：配置副本 + 操作日志摘录 ---------------
m.log_both("config_resign", "tester", "engineer",
           {"dir": m.CONFIG_DIR_APP, "files": 8, "reason": "测试变更",
            "superseded": "release-build"})
out2 = m.build_evidence_pack("工程师", "engineer")
walked = []
for _root, _dirs, _names in os.walk(out2):
    for _n in _names:
        walked.append(os.path.relpath(os.path.join(_root, _n), out2).replace("\\", "/"))
man2 = json.load(open(os.path.join(out2, "manifest.json"), encoding="utf-8"))
cfg_sec = man2.get("config") or {}
check("[10] manifest 含 config 段", bool(cfg_sec) and cfg_sec.get("file_count") == 8,
      f"file_count={cfg_sec.get('file_count')}")
check("[10b] 含受控配置副本", "受控配置_副本/critical_values.yaml" in walked, str(sorted(walked))[:120])
check("[10c] 副本纳入哈希校验", "受控配置_副本/critical_values.yaml" in (man2.get("files") or {}))
check("[10d] 含操作日志摘录", "操作日志摘录_op_log.jsonl" in walked)
_raw = open(os.path.join(out2, "操作日志摘录_op_log.jsonl"), encoding="utf-8").read()
check("[10e] 摘录不含绝对路径", ("E:\\" not in _raw) and ("C:\\" not in _raw),
      _raw.splitlines()[0][:90] if _raw else "")
check("[10f] 摘录含 config_resign 动作", "config_resign" in _raw)
import zipfile as _zip
with _zip.ZipFile(out2 + ".zip") as _z:
    _names_in_zip = _z.namelist()
check("[10g] ZIP 递归含子目录", any("受控配置_副本" in n for n in _names_in_zip),
      f"{len(_names_in_zip)} 条目")


# ---- [11] 重签留痕（N-02）：原因 / 次数 / 被覆盖的原签署人 -----------------
m.sign_config_integrity("工程师", reason="调整危急值阈值经科室确认")
_chk2 = m.verify_config_integrity()
_txt = open(m.CONFIG_MANIFEST, encoding="utf-8").read()
check("[11] 重签写入变更原因", "变更原因：调整危急值阈值经科室确认" in _txt)
check("[11b] 重签次数递增", _chk2.get("resign_count", 0) >= 1, str(_chk2.get("resign_count")))
check("[11c] 记录被覆盖的原签署人", _chk2.get("superseded") == "tester",
      str(_chk2.get("superseded")))


# ---- [12] 危急值判定（N-04/N-05）：阈值驱动，不靠文案 ----------------------
check("[12] K 7.2 判危急", m.judge_critical("K", "7.2") == "urgent")
check("[12b] K 4.0 不判危急", m.judge_critical("K", 4.0) == "")
check("[12c] WBC 35 判危急（证明读 8 项受控表而非 4 项硬编码）",
      m.judge_critical("WBC", 35) == "urgent", m.judge_critical("WBC", 35))
check("[12d] 未知项目不判", m.judge_critical("XXX", 99) == "")
check("[12e] 非数值不判", m.judge_critical("K", "abc") == "")
check("[12f] severity 字段优先", m._is_critical({"content": "K 7.2", "severity": "urgent"}))
check("[12g] severity=normal 压过文案关键词",
      not m._is_critical({"content": "危急值 报告", "severity": "normal"}))
check("[12h] 无 severity 时回落关键词", m._is_critical({"content": "危急值 报告"}))


# ---- [13] 口令落盘混淆（N-07）-------------------------------------------
m.load_users()  # 触发迁移写盘
_rawu = open(m.USERS_FILE, encoding="utf-8").read()
check("[13] 口令不明文落盘", ("1111" not in _rawu) and ("enc:v1:" in _rawu))
_us = m.load_users()
check("[13b] 读回口令为明文", _us[0]["password"] == "1111", _us[0]["password"])


# ---- [14] 职责分离（N-06）：录入人字段 -----------------------------------
m.sink_records([{"type": "检验结果", "content": "GLU 5.0 mmol/L"}],
               source="test", actor="检验员", role="technician")
_last = m.load_records()[-1]
check("[14] 记录含 created_by", _last.get("created_by") == "检验员", str(_last.get("created_by")))
check("[14b] 记录含 created_role/created_at",
      _last.get("created_role") == "technician" and bool(_last.get("created_at")))


# ---- [15] 恢复后哈希链完整（V2.5.1 修复：归档段残留导致误报断链） --------
# 场景：备份 → 之后日志轮转（新增归档段）→ 再写几条 → 恢复
# 期望：恢复后新增的归档段被撤销，链完整，条数回到备份时点。
_bk = os.path.join(TMP, "restore_probe.zip")
m.backup_data(_bk)
_log = m.DATA_LOG_H
_n_before = _log.count()
_a_before = len(_log._archive_files())
_orig_rotate = _log.ROTATE_BYTES
_log.ROTATE_BYTES = 0          # 强制下一次写入触发轮转（走生产代码路径，不手改文件名）
m.log_both("post_backup_rotate", "工程师", "engineer", {})
_log.ROTATE_BYTES = _orig_rotate
check("[15] 备份后发生轮转（新增 1 个归档段）",
      len(_log._archive_files()) == _a_before + 1,
      "%d → %d" % (_a_before, len(_log._archive_files())))
_r = m.restore_data(_bk)
_log._head = None
_c = _log.verify_chain()
check("[15] 恢复后链完整且条数回到备份时点",
      _c.get("ok") is True and _c.get("count") == _n_before,
      "%s（备份时 %d）" % (_c, _n_before))
check("[15] 备份后新增的归档段已撤销",
      len(_log._archive_files()) == _a_before,
      "归档段 %d，应 %d" % (len(_log._archive_files()), _a_before))
check("[15] 恢复前数据已整体移出（可回退）",
      os.path.isdir(_r.get("replaced_to", "")) and _r.get("replaced_count", 0) > 0,
      str(_r.get("replaced_to")))
check("[15] 恢复产生安全备份", os.path.exists(_r.get("safety_backup", "")))


# ---- [16] NHANES 默认数据路径向上搜索（V2.5.2 修复） --------------------
# 场景：交付封包布局下 code/../../公开数据/ 不存在，默认路径必须能
# 逐级向上找到 公开数据/CBC_L.xpt（真实布局）与合成布局（cwd 上溯）。
_nspec = importlib.util.spec_from_file_location(
    "lb_nhanes_t", os.path.join(HERE, "code", "labbridge_nhanes.py"))
_nmod = importlib.util.module_from_spec(_nspec)
_nspec.loader.exec_module(_nmod)
_real = _nmod.find_public_data("CBC_L.xpt")
check("[16] 真实布局默认路径可解析", os.path.isfile(_real), _real)
_synth_root = tempfile.mkdtemp(prefix="lb_v240_pub_")
_synth_leaf = os.path.join(_synth_root, "a", "b", "c")
os.makedirs(_synth_leaf)
os.makedirs(os.path.join(_synth_root, "公开数据"))
_synth_xpt = os.path.join(_synth_root, "公开数据", "FAKE_L.xpt")
open(_synth_xpt, "wb").write(b"synthetic")
_cwd = os.getcwd()
try:
    os.chdir(_synth_leaf)
    _got = _nmod.find_public_data("FAKE_L.xpt")
finally:
    os.chdir(_cwd)
check("[16] 合成布局 cwd 上溯可解析", os.path.normpath(_got) == os.path.normpath(_synth_xpt),
      _got)
shutil.rmtree(_synth_root, ignore_errors=True)


print("\n==== 汇总：%d/%d PASS ====" % (sum(1 for _, c, _ in OK if c), len(OK)))
failed = [n for n, c, _ in OK if not c]
if failed:
    print("未通过：" + "；".join(failed))
shutil.rmtree(TMP, ignore_errors=True)
shutil.rmtree(BASE_TMP, ignore_errors=True)
sys.exit(0 if not failed else 1)
