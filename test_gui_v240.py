# -*- coding: utf-8 -*-
"""V2.4 GUI 构建冒烟：真实 Tk 下实例化全部 11 个页签，捕获构造期异常。"""
import json
import os
import shutil
import sys
import tempfile
import tkinter as tk

sys.argv = ["test_gui"]
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("v2app", os.path.join(HERE, "labbridge_v2_app.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

TMP = tempfile.mkdtemp(prefix="lb_gui_")
m.HOME_DIR = TMP
m.USERS_FILE = os.path.join(TMP, "users.json")
m.RECORDS_FILE = os.path.join(TMP, "records.json")
m.API_CONFIG_FILE = os.path.join(TMP, "api_config.json")
m.EVIDENCE_ROOT = os.path.join(TMP, "evidence")
m.API_AUDIT = os.path.join(TMP, "api_audit.jsonl")
m.DATA_LOG_H = m.HashChainLog(os.path.join(TMP, "data_log.jsonl"))
m.OP_LOG_H = m.HashChainLog(os.path.join(TMP, "op_log.jsonl"))
m.seed_records()
m.log_both("smoke", "工程师", "engineer", {"x": 1})

root = tk.Tk()
root.withdraw()


class Stub:
    current_user = {"username": "工程师", "role": "engineer", "level": 1}
    config_check = {"ok": True, "status": "signed"}
    api_state = m.load_api_state()
    tabs = {}

    def require_login(self):
        return True

    def _refresh_config_badge(self):
        pass


stub = Stub()
nb = tk.Frame(root)
classes = [("主页", m.HomePanel), ("API 接口", m.ApiPanel), ("人员管理", m.PeoplePanel),
           ("检验数据结果", m.ResultsPanel), ("记录管理", m.RecordsPanel),
           ("敏感信息查看", m.SensitivePanel), ("云端配置", m.CloudPanel),
           ("日志溯源", m.TracePanel), ("风险热力图", m.HeatmapPanel),
           ("PDCA 工具", m.PdcaPanel), ("证据包", m.EvidencePanel)]
ok = 0
for name, cls in classes:
    try:
        w = cls(nb, stub)
        stub.tabs[name] = w
        print(f"PASS 构建 {name}")
        ok += 1
    except Exception as e:
        import traceback
        print(f"FAIL 构建 {name}: {type(e).__name__}: {e}")
        traceback.print_exc()

# 记录页筛选与危急值标红
rp = stub.tabs["检验结果数据结果"] if False else stub.tabs["检验数据结果"]
m.sink_records([{"type": "检验结果", "content": "GLU 24.6 mmol/L（偏高）"},
                {"type": "待发列表", "content": "待关注（urgent）K 7.2 危急值"}], source="smoke")
rp.refresh()
rows = rp.tree.get_children()
tags = rp.tree.item(rows[-1], "tags") if rows else ()
expect = sum(1 for r in m.load_records() if r["type"] in rp.DATA_TYPES)
print(f"{'PASS' if len(rows) == expect else 'FAIL'} 结果页显示 {len(rows)} 行（应 {expect}）")
print(f"{'PASS' if 'critical' in tags else 'FAIL'} 危急行标红 tags={tags}")
rp.kw.insert(0, "urgent")
rp.refresh()
print(f"{'PASS' if len(rp.tree.get_children()) == 1 else 'FAIL'} 关键字筛选命中 {len(rp.tree.get_children())} 行")
rp.reset()

# 日志溯源三源切换
tp = stub.tabs["日志溯源"]
tp.src.set("处置审计")
tp.refresh_hint()
print(f"{'PASS' if 'api_audit' in tp.hint.cget('text') else 'FAIL'} 日志源提示：{tp.hint.cget('text')}")
tp.src.set("数据结果日志")
tp.refresh_hint()
print(f"{'PASS' if 'data_log' in tp.hint.cget('text') else 'FAIL'} 日志源提示：{tp.hint.cget('text')}")

root.destroy()
shutil.rmtree(TMP, ignore_errors=True)
print(f"\n==== 页签构建 {ok}/{len(classes)} ====")
sys.exit(0 if ok == len(classes) else 1)
