# -*- coding: utf-8 -*-
"""云端配置模块接口一致性测试（无头，可脱离 GUI 运行）。"""
import json
import os
import socket
import sys
import tempfile
import threading

sys.argv = ["t"]

import importlib.util
spec = importlib.util.spec_from_file_location("v2app", "labbridge_v2_app.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

passed, failed = [], []


def check(name, cond):
    (passed if cond else failed).append(name)
    print(("PASS " if cond else "FAIL ") + name)


# ---- 1. 参数校验 validate_cloud_cfg ----
ok, _ = m.validate_cloud_cfg({"type": "外置服务器", "addr": "192.168.1.10", "port": "8080"})
check("校验-合法配置通过", ok)
ok, _ = m.validate_cloud_cfg({"type": "医院内网", "addr": "", "port": "8080"})
check("校验-地址为空允许(内网留档)", ok)
ok, _ = m.validate_cloud_cfg({"type": "医院内网", "addr": "nas-01.hospital.local", "port": 443})
check("校验-整数端口/主机名通过", ok)
for bad, why in [
    ({"type": "阿里云", "addr": "", "port": "8080"}, "非法类型"),
    ({"type": "外网", "addr": "http://10.0.0.1", "port": "8080"}, "地址含协议头"),
    ({"type": "外网", "addr": "a b.c", "port": "8080"}, "地址含空格"),
    ({"type": "外网", "addr": "x" * 300, "port": "8080"}, "地址超长"),
    ({"type": "外网", "addr": "10.0.0.1", "port": "abc"}, "端口非数字"),
    ({"type": "外网", "addr": "10.0.0.1", "port": "0"}, "端口为0"),
    ({"type": "外网", "addr": "10.0.0.1", "port": "65536"}, "端口超上界"),
    ({"type": "外网", "addr": "10.0.0.1", "port": "-1"}, "端口为负"),
    ({"type": "外网", "addr": "10.0.0.1", "port": ""}, "端口为空"),
    ({"type": "外网", "addr": "10.0.0.1"}, "缺端口键"),
    ("not a dict", "非对象"),
]:
    ok, err = m.validate_cloud_cfg(bad)
    check("校验-拒绝:" + why + "（" + (err[:24] + "…") if len(err) > 24 else err + "）", not ok and bool(err))

# ---- 2. 保存/读取回环 load_cloud_config ----
tmp = tempfile.mkdtemp()
old_home = m.HOME_DIR
m.HOME_DIR = tmp
p = m.cloud_config_path()
cfg0, warn = m.load_cloud_config()
check("读取-文件缺失回默认值", cfg0 == {"type": "医院内网", "addr": "", "port": "8080"} and warn is None)
good = {"type": "外置服务器", "addr": "192.168.1.10", "port": "9000"}
with open(p, "w", encoding="utf-8") as f:
    json.dump(good, f, ensure_ascii=False)
cfg1, warn = m.load_cloud_config()
check("读取-合法配置原样回读", cfg1 == good and warn is None)
with open(p, "w", encoding="utf-8") as f:
    f.write('{"type": "外置服务器", "addr": ')
cfg2, warn = m.load_cloud_config()
check("读取-损坏JSON回默认值并告警", cfg2["type"] == "医院内网" and bool(warn))
with open(p, "w", encoding="utf-8") as f:
    json.dump({"type": " hacker", "addr": "", "port": "1"}, f)
cfg3, warn = m.load_cloud_config()
check("读取-不合法内容回默认值并告警", cfg3["type"] == "医院内网" and bool(warn))
with open(p, "w", encoding="utf-8") as f:
    f.write("\xff\xfe not utf8")
cfg4, warn = m.load_cloud_config()
check("读取-非UTF8文件回默认值并告警", cfg4["type"] == "医院内网" and bool(warn))

# ---- 3. 连通测试 test_cloud_connect ----
srv = socket.socket()
srv.bind(("127.0.0.1", 0))
srv.listen(1)
free_port = srv.getsockname()[1]
r = m.test_cloud_connect("127.0.0.1", free_port, timeout=2)
check("连通-在线端口 ok+时延为正数", r["ok"] is True and r["latency_ms"] >= 0 and r["error"] == "")
srv.close()
r = m.test_cloud_connect("127.0.0.1", free_port, timeout=2)
check("连通-离线端口返回ok=False+原因", r["ok"] is False and bool(r["error"]))
r = m.test_cloud_connect("256.256.256.256", 80, timeout=2)
check("连通-非法主机返回ok=False", r["ok"] is False and bool(r["error"]))

m.HOME_DIR = old_home

print()
print(f"合计 {len(passed)} PASS / {len(failed)} FAIL")
if failed:
    print("失败项:", failed)
    sys.exit(1)
