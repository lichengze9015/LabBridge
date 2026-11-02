#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LabBridge 配置层 —— 纯标准库实现（含 YAML 子集解析器）

Provenance / 反溯说明
---------------------
本文件为独立编写，仅依赖 Python 标准库。
内嵌一个 YAML 子集解析器（`miniyaml`），**未参考 PyYAML / ruamel.yaml 的源码**，
依据的是 YAML 1.2 公开规范中「缩进表示层级、`- ` 表示序列、`key: value` 表示映射」
这一公开语法约定。

为什么要自带解析器：
    文档 05 要求分级规则、权限矩阵必须是「人签署 + 时间戳锚定」的受控文件，
    形态规定为 YAML / CSV；而 Demo 目标是能跑在乡镇卫生院一台没有任何 pip 环境的
    普通电脑上。为了不把「读配置」这件事绑死在 PyYAML 上，这里实现一个覆盖本项目
    配置所用语法子集的解析器。若环境中已安装 PyYAML，会自动优先使用它
    （见 `load_yaml`，可通过 `LABBRIDGE_FORCE_MINIYAML=1` 强制走内置解析器）。

支持的 YAML 子集：
    - `#` 整行注释、空行
    - 缩进映射（2 空格）、`key: value`
    - 序列 `- item` 与序列套映射 `- key: value`
    - 标量：字符串（含单/双引号）、整数、浮点、true/false、null
    - 流式容器：`{a: 1, b: 2}`、`[1, 2, 3]`
不支持：锚点(&/*)、多文档(---)、块标量(|/>)、标签(!!)、行尾注释。
"""

import csv
import os
import sys
from typing import Any, Dict, List, Tuple

# ---------------------------------------------------------------------------
# miniyaml —— YAML 子集解析器
# ---------------------------------------------------------------------------


class MiniYamlError(ValueError):
    """YAML 子集解析失败。"""


def _split_flow(s: str) -> List[str]:
    """按逗号切分流式容器内容，忽略引号与嵌套括号内的逗号。"""
    out, buf, depth = [], [], 0
    quote = None
    for ch in s:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch in "[{":
            depth += 1
            buf.append(ch)
        elif ch in "]}":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if "".join(buf).strip():
        out.append("".join(buf).strip())
    return out


# YAML 双引号标量转义（V3 修复：原实现不处理转义，导致无 PyYAML 环境下
# classification_rules.yaml 的 leak_patterns 正则（"1[3-9]\\d{9}"）加载为
# 字面双反斜杠，泄漏回扫永不命中、自检第 9 项 FAIL——脱敏红线静默失效）
_DQ_ESCAPES = {
    "\\": "\\", '"': '"', "/": "/", "n": "\n", "t": "\t", "r": "\r",
    "0": "\0", "b": "\b", "f": "\f", "v": "\v",
}


def _unescape_dq(body: str) -> str:
    """双引号标量反转义：支持 YAML 常用转义，\\x/\\u 按码点还原。"""
    out = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt in _DQ_ESCAPES:
                out.append(_DQ_ESCAPES[nxt])
                i += 2
                continue
            if nxt in ("x", "u"):
                n = 2 if nxt == "x" else 4
                try:
                    out.append(chr(int(body[i + 2:i + 2 + n], 16)))
                    i += 2 + n
                    continue
                except ValueError:
                    pass
            out.append(nxt)  # 未识别转义：丢弃反斜杠，保字符（YAML 允许）
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _scalar(tok: str) -> Any:
    tok = tok.strip()
    if not tok:
        return None
    if len(tok) >= 2 and tok[0] == '"' and tok[-1] == '"':
        return _unescape_dq(tok[1:-1])
    if len(tok) >= 2 and tok[0] == "'" and tok[-1] == "'":
        return tok[1:-1].replace("''", "'")
    if tok.startswith("[") and tok.endswith("]"):
        inner = tok[1:-1].strip()
        return [] if not inner else [_scalar(x) for x in _split_flow(inner)]
    if tok.startswith("{") and tok.endswith("}"):
        inner = tok[1:-1].strip()
        if not inner:
            return {}
        d: Dict[str, Any] = {}
        for part in _split_flow(inner):
            k, sep, v = part.partition(":")
            if not sep:
                raise MiniYamlError(f"流式映射缺少冒号: {part!r}")
            d[str(_scalar(k))] = _scalar(v)
        return d
    low = tok.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~"):
        return None
    try:
        return int(tok)
    except ValueError:
        pass
    try:
        return float(tok)
    except ValueError:
        pass
    return tok


def _tokenize(text: str) -> List[Tuple[int, str]]:
    lines: List[Tuple[int, str]] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # 去掉行尾注释（仅在未处于引号内时）
        cut = len(raw)
        quote = None
        for idx, ch in enumerate(raw):
            if quote:
                if ch == quote:
                    quote = None
            elif ch in "\"'":
                quote = ch
            elif ch == "#" and (idx == 0 or raw[idx - 1] in " \t"):
                cut = idx
                break
        raw = raw[:cut].rstrip()
        stripped = raw.strip()
        if not stripped:
            continue
        lines.append((len(raw) - len(raw.lstrip()), stripped))
    return lines


def _parse_map(lines, i, indent):
    d: Dict[str, Any] = {}
    while i < len(lines):
        ind, content = lines[i]
        if ind < indent:
            break
        if ind > indent:
            raise MiniYamlError(f"缩进异常于第 {i} 行: {content!r}")
        if content.startswith("- "):
            break
        key, sep, val = content.partition(":")
        if not sep:
            raise MiniYamlError(f"缺少冒号: {content!r}")
        k = str(_scalar(key))
        v = val.strip()
        if v:
            d[k] = _scalar(v)
            i += 1
            continue
        nxt = i + 1
        if nxt < len(lines) and lines[nxt][0] > indent:
            d[k], i = _parse_block(lines, nxt, lines[nxt][0])
        elif nxt < len(lines) and lines[nxt][0] == indent and lines[nxt][1].startswith("- "):
            d[k], i = _parse_list(lines, nxt, indent)
        else:
            d[k] = None
            i += 1
    return d, i


def _parse_list(lines, i, indent):
    items: List[Any] = []
    while i < len(lines):
        ind, content = lines[i]
        if ind < indent:
            break
        if ind > indent:
            raise MiniYamlError(f"缩进异常于第 {i} 行: {content!r}")
        if not content.startswith("-") or (content != "-" and not content.startswith("- ")):
            break
        body = content[1:].strip()
        if not body:
            nxt = i + 1
            if nxt < len(lines) and lines[nxt][0] > indent:
                val, i = _parse_block(lines, nxt, lines[nxt][0])
            else:
                val, i = None, nxt
            items.append(val)
            continue
        if not body.startswith(("{", "[")) and ":" in body:
            sub = [(indent + 2, body)]
            j = i + 1
            cont = []
            while j < len(lines) and lines[j][0] > indent:
                cont.append(lines[j])
                j += 1
            if cont:
                base = min(x[0] for x in cont)
                sub.extend((indent + 2 + (x[0] - base), x[1]) for x in cont)
            val, _ = _parse_map(sub, 0, indent + 2)
            items.append(val)
            i = j
        else:
            items.append(_scalar(body))
            i += 1
    return items, i


def _parse_block(lines, i, indent):
    ind, content = lines[i]
    if content == "-" or content.startswith("- "):
        return _parse_list(lines, i, ind)
    return _parse_map(lines, i, ind)


def miniyaml(text: str) -> Any:
    lines = _tokenize(text)
    if not lines:
        return None
    value, idx = _parse_block(lines, 0, lines[0][0])
    if idx != len(lines):
        raise MiniYamlError(f"未能消费全部行，停在第 {idx} 行: {lines[idx][1]!r}")
    return value


def load_yaml(path: str) -> Any:
    """读取 YAML。优先 PyYAML（若已安装且未强制禁用），否则用内置解析器。"""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if not os.environ.get("LABBRIDGE_FORCE_MINIYAML"):
        try:
            import yaml  # type: ignore
            return yaml.safe_load(text)
        except ImportError:
            pass
    return miniyaml(text)


def load_csv(path: str) -> List[Dict[str, str]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        return [dict(row) for row in csv.DictReader(f)]


# ---------------------------------------------------------------------------
# 配置集
# ---------------------------------------------------------------------------

_HERE = os.path.dirname(os.path.abspath(__file__))


def _resolve_config_dir() -> str:
    """受控配置目录查找顺序（V3 修复：EXE 冻结环境下 __file__ 位于临时
    解包目录，原实现会去找 <临时目录>/../config 导致启动即缺文件）：
      1. 环境变量 LABBRIDGE_CONFIG（显式指定，最高优先）
      2. EXE 同级 config\\（主程序包自包含形态）
      3. EXE 上级目录 config\\（独立 EXE 与 app\\config 同级形态）
      4. 源码形态：<code/../config（开发环境）"""
    env = os.environ.get("LABBRIDGE_CONFIG")
    if env:
        return os.path.normpath(env)
    exe_dir = os.path.dirname(sys.executable)
    if getattr(sys, "frozen", False):
        for cand in (os.path.join(exe_dir, "config"),
                     os.path.normpath(os.path.join(exe_dir, "..", "config"))):
            if os.path.isdir(cand):
                return cand
    return os.path.normpath(os.path.join(_HERE, "..", "config"))


CONFIG_DIR = _resolve_config_dir()


def config_path(name: str) -> str:
    return os.path.join(CONFIG_DIR, name)


def _need(name: str) -> Any:
    p = config_path(name)
    if not os.path.exists(p):
        raise FileNotFoundError(f"缺少受控配置文件: {p}")
    return load_yaml(p)


class Config:
    """受控配置集。所有规则来自人签署的文件，代码里不硬编码业务判断。"""

    def __init__(self, config_dir: str = None):
        self.dir = config_dir or CONFIG_DIR
        self.classification = _need("classification_rules.yaml")
        self.screening = _need("screening_rules.yaml")
        self.critical = _need("critical_values.yaml")
        self.roles = _need("roles.yaml")
        self.acceptance = _need("acceptance.yaml")
        self.stage_gate = _need("stage_gate.yaml")
        self.access_map = load_csv(config_path("access_map.csv"))
        self.risk_register = load_csv(config_path("risk_register.csv"))

    @property
    def field_class(self) -> Dict[str, str]:
        return self.classification.get("field_class", {})

    @property
    def form_matrix(self) -> Dict[str, Dict[str, str]]:
        return self.roles.get("form_matrix", {})


# ---------------------------------------------------------------------------
# 自检
# ---------------------------------------------------------------------------

_SAMPLE = """
# 注释行
meta:
  version: 1.0
  signed_by: "张三"
  enabled: true
  ratio: 0.95
  nothing: null
rules:
  - id: R1
    name: 异常标志聚合
    action: flag
  - id: R2
    name: 危急值预筛
    params: {window_days: 7, drift_pct: 30}
    action: flag_urgent
inline_list: [a, b, 3]
output:
  forbidden_wording: ["已审核", "已签发"]
"""


def selftest() -> int:
    print("== labbridge_config 自检 ==")
    ok = True

    data = miniyaml(_SAMPLE)
    checks = [
        ("meta.version", data["meta"]["version"] == 1.0),
        ("signed_by 引号", data["meta"]["signed_by"] == "张三"),
        ("bool", data["meta"]["enabled"] is True),
        ("float", abs(data["meta"]["ratio"] - 0.95) < 1e-9),
        ("null", data["meta"]["nothing"] is None),
        ("序列套映射", data["rules"][0]["id"] == "R1" and data["rules"][0]["name"] == "异常标志聚合"),
        ("流式映射", data["rules"][1]["params"]["window_days"] == 7),
        ("流式序列", data["inline_list"] == ["a", "b", 3]),
        ("中文列表", data["output"]["forbidden_wording"] == ["已审核", "已签发"]),
        ("注释未入值", "注释行" not in str(data)),
    ]
    for label, passed in checks:
        print(f"  [{'OK' if passed else 'FAIL'}] {label}")
        ok &= passed

    # 与 PyYAML 交叉校验（若可用）
    try:
        import yaml  # type: ignore
        same = yaml.safe_load(_SAMPLE) == data
        print(f"  [{'OK' if same else 'FAIL'}] 与 PyYAML 结果一致")
        ok &= same
    except ImportError:
        print("  [SKIP] PyYAML 未安装，跳过交叉校验")

    try:
        cfg = Config()
        print(f"  [OK] 配置集加载: {len(cfg.field_class)} 字段, "
              f"{len(cfg.form_matrix)} 角色, {len(cfg.risk_register)} 条风险")
    except Exception as e:
        print(f"  [FAIL] 配置集加载: {e}")
        ok = False

    print("结果:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
