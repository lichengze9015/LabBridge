# LabBridge Demo — 代码模块

本目录包含 13 个模块。**前 4 个为黄灯区重写模块**，依据公开标准与协议规范独立编写，
用于替代文档 09 中黄灯区的组件；**后 9 个为本轮封包新增**，补齐社区无合适资产的能力缺口。
每个源文件头部都有 `Provenance` 段，说明「依据什么写的、没参考什么」。

| 文件 | 替代对象 | 依赖 | License 影响 |
|---|---|---|---|
| `labbridge_mcp.py` | modelcontextprotocol/servers（MIT→Apache 过渡期） | 无（纯标准库） | 自有代码 |
| `labbridge_docparse.py` | MinerU（+商业阈值）/ marker | pypdf BSD-3、python-docx MIT | 仅传递性 |
| `labbridge_report.py` | anthropics/skills 的 docx skill（source-available） | python-docx MIT | 仅传递性 |
| `labbridge_pdca.py` | PDCA 工具集（依据《工具记录清单》自实现） | 无（纯标准库） | 自有代码 |

许可台账见 `THIRD_PARTY_NOTICES.md`。

---

## 本轮新增模块（9 个，全部纯标准库）

| 文件 | 补齐的能力 | 依赖 |
|---|---|---|
| `labbridge_config.py` | 受控配置层 + 内置 YAML 子集解析器（已装 PyYAML 时优先用，两者结果做过交叉校验） | 无 |
| `labbridge_auditlog.py` | 哈希链审计日志（16 字段 Schema、篡改/删除可检出、受控文件锚定） | 无 |
| `labbridge_astm.py` | ASTM E1381/E1394 **只读**接收端（passive/tcp/serial/replay/simulate） | 无 |
| `labbridge_deid.py` | 字段级 + 行级脱敏与访问控制（三层模型：人定规则/机器执行/人审例外） | 无 |
| `labbridge_screen.py` | 三条审核规则 + 熔断检测 + 措辞合规 + 一致率评估 | 无 |
| `labbridge_ocr.py` | OCR 后端适配 + 结构化抽取 + 人工确认队列（不含任何 OCR 引擎代码） | 无（引擎可选） |
| `labbridge_evidence.py` | 证据包 / 离线资产包 / 验收断言 / CAPA 闭环 | 无 |
| `labbridge_gate.py` | 红线自检 / 阶段门 / 审批门（四要素 + 超时默认拒绝） | 无 |
| `labbridge_demo.py` | 端到端编排器，串起双轨并产出证据包 | 无 |

> 坚持零依赖的理由：Demo 要能跑在乡镇卫生院一台没有 pip 环境的普通电脑上，
> 且与「业务资产解耦、可离线交付」的诉求一致（文档 02 目标 4、文档 08 第四章）。

## 环境

```bash
pip install python-docx pypdf      # 仅 docparse/report 需要；其余 11 个模块零依赖
```

## 自检

```bash
# 全部 13 个模块
for m in config auditlog astm deid screen gate ocr evidence demo mcp docparse report pdca; do
  python labbridge_$m.py --selftest
done

# 或者单独跑
python labbridge_mcp.py --selftest
python labbridge_docparse.py --selftest
python labbridge_report.py --selftest
python labbridge_pdca.py --selftest      # 36 个工具逐项断言
```

## 一键跑通 Demo

```bash
python labbridge_demo.py --run --samples 50 --output ../output
```

配置文件在 `../config/`，均为**人签署的受控规则文件**（外审检查对象）。

## 使用

```bash
# MCP server（stdio，供 MCP 客户端连接）
python labbridge_mcp.py

# 文档解析 → RAG 语料
python labbridge_docparse.py 文档1.md 文档2.pdf -o chunks.jsonl

# 生成阶段三交付物
python labbridge_report.py --type risk --output 敏感数据接入专项风险评估报告.docx

# PDCA 工具集全量运行（输出到 ../output/）
python labbridge_pdca.py --run -o ../output
```

审计日志默认落 `audit_log.jsonl`，可用 `LABBRIDGE_AUDIT_LOG` 环境变量改路径。

## labbridge_pdca.py — PDCA 工具集

依据《工具记录清单》实现的 36 个质量管理工具，按 P→D→C→A 四阶段组织：

- **P 策划（8）**：SIPOC/乌龟图、风险矩阵 RPN、FMEA、SWOT/PEST、目标展开树、策划检查表、MSA、控制计划
- **D 实施（11）**：查检表、分层法、运行图、直方图、SPC 控制图、散布图、GB/T 2828 抽样、计量抽样、PPAP、人工文件符合性检验、Poka-Yoke
- **C 检查（8）**：帕累托图、鱼骨图、箱线图、柱状图/饼图、内审检查表、顾客满意度、质量成本 COQ、能力成熟度
- **A 处置（9）**：5Why、FTA、亲和图、关系图、DOE、CAPA、对策表、8D、DMAIC

三个要点：

1. **四个预留 API 接口默认全部关闭**（`astm_ingest` / `ocr_extract` / `lis_writeback` / `cloud_llm`），
   开启需人工审批四要素（动作计划、预期影响、风险提示、回滚方案），超时默认拒绝；
2. **审计日志带哈希链**（`prev_hash`/`hash` + `seq` 自增序号），篡改或缺失可检出；
3. **报告含「需人工关注项」章节**——工具状态 PASS 不等于结果无风险，
   掩盖效应、阻塞项、未闭合步骤会被单独列出，不得由系统自动关闭。
