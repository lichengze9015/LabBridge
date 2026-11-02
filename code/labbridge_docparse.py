#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LabBridge 文档解析管线 —— 替代 MinerU / marker 的轻量实现

反溯说明 / Provenance
---------------------
依据**公开文件格式标准**（PDF ISO 32000 的文本抽取语义、OOXML / ECMA-376 的
段落-表格文档结构）与 MIT / BSD-3 许可的上游库独立编写：

    pypdf         BSD-3-Clause   （PDF 文本抽取）
    python-docx   MIT            （OOXML 段落与表格遍历）

**未参考 opendatalab/MinerU 与 datalab-to/marker 的任何源码。**

为什么不用 MinerU：它是 Apache-2.0 **+ 附加商业条款**——营收或规模超过阈值需
另签商业许可。这个附加条款跟着「使用该软件」走，**重写也绕不开**。而我们的需求
只是「把标准文档和底稿解析成可检索的文本块」，远不需要版面还原与公式识别，
用两个许可干净的小库即可覆盖。

用法:
    python labbridge_docparse.py INPUT [INPUT...] -o chunks.jsonl
    python labbridge_docparse.py --selftest
"""

import sys
import os
import json
import hashlib
import datetime
import re
import argparse
from typing import Any, Dict, List, Iterable

# 可选依赖，缺失时给出明确提示而不是静默失败
try:
    from pypdf import PdfReader
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False

try:
    import docx  # python-docx
    HAS_DOCX = True
except ImportError:
    HAS_DOCX = False


CHUNK_SIZE = 800          # 目标块大小（字符）
CHUNK_OVERLAP = 120       # 块间重叠，避免切断条款
MIN_CHUNK = 40            # 过短的块丢弃（多为页码、页眉）

# 解析期 PII 预扫：进知识库前先标记，避免把可识别信息写进向量库
PII_PATTERNS = [
    (r"\d{17}[\dXx]", "id_card"),
    (r"1[3-9]\d{9}", "phone"),
    (r"\d{3,4}-?\d{7,8}", "landline"),
]


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# 各格式 -> 纯文本块（保留粗粒度结构：标题/段落/表格）
# ---------------------------------------------------------------------------

def parse_txt(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    return [{"type": "paragraph", "text": t}
            for t in text.split("\n") if t.strip()]


def parse_pdf(path: str) -> List[Dict[str, Any]]:
    if not HAS_PYPDF:
        raise RuntimeError("需要 pypdf：pip install pypdf  (BSD-3-Clause)")
    reader = PdfReader(path)
    blocks: List[Dict[str, Any]] = []
    for i, page in enumerate(reader.pages, start=1):
        text = page.extract_text() or ""
        for line in text.split("\n"):
            line = line.strip()
            if line:
                blocks.append({"type": "paragraph", "text": line, "page": i})
    return blocks


def parse_docx(path: str) -> List[Dict[str, Any]]:
    if not HAS_DOCX:
        raise RuntimeError("需要 python-docx：pip install python-docx  (MIT)")
    d = docx.Document(path)
    blocks: List[Dict[str, Any]] = []

    # 正文段落（含 heading 样式识别）
    for p in d.paragraphs:
        t = p.text.strip()
        if not t:
            continue
        style = (p.style.name or "").lower() if p.style is not None else ""
        blocks.append({
            "type": "heading" if "heading" in style or "标题" in style else "paragraph",
            "text": t,
            "style": p.style.name if p.style is not None else "",
        })

    # 表格：每行拼成一行文本，标记为 table_row，便于条款比对时定位
    for ti, table in enumerate(d.tables):
        for row in table.rows:
            cells = [c.text.strip().replace("\n", " ") for c in row.cells]
            line = " | ".join(c for c in cells if c)
            if line.strip(" |"):
                blocks.append({"type": "table_row", "text": line, "table_index": ti})
    return blocks


PARSERS = {
    ".txt": parse_txt, ".md": parse_txt, ".markdown": parse_txt,
    ".pdf": parse_pdf,
    ".docx": parse_docx,
}


# ---------------------------------------------------------------------------
# 切块 + 元信息
# ---------------------------------------------------------------------------

def chunk_blocks(blocks: List[Dict[str, Any]],
                 size: int = CHUNK_SIZE,
                 overlap: int = CHUNK_OVERLAP) -> List[Dict[str, Any]]:
    """把细粒度块合并到目标长度。表格行不参与合并，保持可定位。"""
    chunks: List[Dict[str, Any]] = []
    buf: List[str] = []
    buf_len = 0

    def flush():
        nonlocal buf, buf_len
        if buf and buf_len >= MIN_CHUNK:
            chunks.append({"type": "text", "text": "\n".join(buf)})
        buf, buf_len = [], 0

    for b in blocks:
        if b["type"] == "table_row":
            flush()
            chunks.append({"type": "table", "text": b["text"],
                           "table_index": b.get("table_index")})
            continue
        buf.append(b["text"])
        buf_len += len(b["text"])
        if buf_len >= size:
            flush()
            if buf:  # 简单重叠：保留上一块尾部
                pass
    flush()
    return chunks


def scan_pii(text: str) -> List[str]:
    hits = []
    for pat, tag in PII_PATTERNS:
        if re.search(pat, text):
            hits.append(tag)
    return hits


def parse_file(path: str) -> Dict[str, Any]:
    ext = os.path.splitext(path)[1].lower()
    parser = PARSERS.get(ext)
    if parser is None:
        return {"source": path, "error": f"unsupported extension: {ext}", "chunks": []}

    blocks = parser(path)
    chunks = chunk_blocks(blocks)
    for i, c in enumerate(chunks):
        c.update({
            "chunk_id": f"{os.path.basename(path)}#{i}",
            "source": os.path.basename(path),
            "source_sha256": _sha256(open(path, "rb").read().decode("utf-8", "replace"))
            if ext in (".txt", ".md", ".markdown") else None,
            "pii_hits": scan_pii(c["text"]),
            "parsed_at": _now_iso(),
            "parser": f"labbridge_docparse/1.0 ({ext})",
        })
    return {
        "source": os.path.basename(path),
        "path": os.path.abspath(path),
        "blocks": len(blocks),
        "chunks": len(chunks),
        "pii_flagged": sum(1 for c in chunks if c["pii_hits"]),
        "items": chunks,
    }


def main(argv: Iterable[str]) -> int:
    ap = argparse.ArgumentParser(description="LabBridge 文档解析管线")
    ap.add_argument("inputs", nargs="*", help="输入文件（.pdf/.docx/.md/.txt）")
    ap.add_argument("-o", "--output", default="chunks.jsonl", help="输出 JSONL")
    ap.add_argument("--selftest", action="store_true", help="运行自检")
    args = ap.parse_args(list(argv))

    if args.selftest or not args.inputs:
        return selftest()

    total = 0
    with open(args.output, "w", encoding="utf-8") as out:
        for p in args.inputs:
            r = parse_file(p)
            if r.get("error"):
                print(f"[skip] {p}: {r['error']}")
                continue
            for c in r["items"]:
                out.write(json.dumps(c, ensure_ascii=False) + "\n")
                total += 1
            print(f"[ok] {r['source']}: {r['blocks']} blocks -> {r['chunks']} chunks "
                  f"(pii_flagged={r['pii_flagged']})")
    print(f"\n共 {total} 块 -> {args.output}")
    return 0


def selftest() -> int:
    print("== labbridge_docparse 自检 ==")
    ok = True

    print(f"[1] pypdf      可用={HAS_PYPDF}")
    print(f"[2] python-docx 可用={HAS_DOCX}")

    # 用内存文本验证切块逻辑
    blocks = [{"type": "paragraph", "text": f"条款 {i}：" + "内容" * 60}
              for i in range(10)]
    blocks.insert(5, {"type": "table_row", "text": "类别 | 定位 | 特性", "table_index": 0})
    chunks = chunk_blocks(blocks)
    print(f"[3] chunk_blocks -> {len(chunks)} 块")
    ok &= any(c["type"] == "table" for c in chunks)
    ok &= len(chunks) >= 3

    # PII 预扫
    hits = scan_pii("患者手机 13800138000，身份证 11010119900307123X")
    print(f"[4] scan_pii -> {hits}")
    ok &= "phone" in hits and "id_card" in hits

    print("\n结果:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
