# THIRD_PARTY_NOTICES

LabBridge Demo — 第三方组件许可台账
生成日期：2026-10-22
维护要求：任一组件版本变更，须同步更新本表，并将旧版条目保留备查（文档 07 第六章）。

---

## 一、运行时依赖（直接引入本项目代码）

| 组件 | 版本 | License | 来源 | 用途 | 状态 |
|---|---|---|---|---|---|
| （无） | — | — | — | `labbridge_mcp.py` **零第三方依赖**，仅 Python 标准库 | ✅ |
| pypdf | 6.21.2 | BSD-3-Clause | PyPI / github.com/py-pdf/pypdf | PDF 文本抽取 | ✅ |
| python-docx | 1.2.0 | MIT | PyPI / github.com/python-openxml/python-docx | 读写 .docx | ✅ |

## 二、建议引入但尚未接入（授权已核实）

| 组件 | License | 用途 | 备注 |
|---|---|---|---|
| labmcp-astm-lis (K-Dense-AI/lab-instrument-mcps) | Apache-2.0 | 轨道 A ASTM 接收 | ★20，早期项目，**须 fork 并锁 commit hash** |
| RapidAI/RapidOCR | Apache-2.0 | 轨道 B 端侧 OCR | 模型权重许可需单独确认 |
| PaddlePaddle/PaddleOCR | Apache-2.0 | OCR 精度回退 | 同上 |
| Presidio (data-privacy-stack/presidio) | MIT | PII 识别与脱敏 | 已从 microsoft 组织迁出 |
| danyuchn/pii-guard | MIT | 中文 PII 补充 | — |
| ollama / llama.cpp | MIT | 敏感场景本地底座 | — |
| modelcontextprotocol/python-sdk | MIT | 若改用官方 SDK 实现 MCP | 本项目目前未使用（自行实现协议层） |
| openpyxl | MIT | 风险登记表 .xlsx 导出 | 按需 |
| python-pptx | MIT | 汇报页 .pptx 生成 | 按需（★3.5k，806d 未更新，功能稳定） |

## 三、❌ 明确排除（及原因）

| 组件 | License | 排除原因 |
|---|---|---|
| **pymupdf/PyMuPDF** | **AGPL-3.0** | 传染性许可，与「业务资产解耦、可闭源交付」冲突。**注意：很多 PDF 教程默认推荐它，务必避开** |
| opendatalab/MinerU | Apache-2.0 + 附加商业条款 | 营收/规模超阈值需另签商业许可；且本场景不需要版面还原 |
| anthropics/skills 中 docx/pdf/pptx/xlsx | **source-available（非开源）** | 明写「source-available, not open source」，只能看不能用 |
| LeapBeyond/scrubadub | Apache-2.0 | 停维护（1147d 未更新） |
| ComposioHQ/awesome-claude-skills | 未声明 | 无法确认授权 |
| AGPL 类项目（CrossPaste 等） | AGPL-3.0 | 传染性 |

## 四、非代码资产的授权边界（重要）

| 资产 | 授权情况 | 本项目处理方式 |
|---|---|---|
| ASTM E1381 / E1394 标准文本 | ASTM International 付费标准，文本受版权保护 | 仅引用协议编号；知识库只放自撰要点笔记，**不存标准原文** |
| CLSI LIS1-A / LIS2-A2 | 同上，CLSI 付费标准 | 同上 |
| LOINC | Regenstrief 免费使用但需接受条款，再分发受限 | Demo 阶段不引入；检测项目只做字符串归一化 + 本地对照表 |
| SNOMED CT | 需成员国/地区许可机构授权 | 不引入 |
| PP-OCR / RapidOCR 模型权重 | 与代码许可分离，需单独确认 | 使用前确认，并记录来源与许可到本表 |

## 五、本轮封包新增模块（均为纯标准库，零新增依赖）

| 模块 | 依赖 | 依据 | 说明 |
|---|---|---|---|
| `labbridge_config.py` | **零** | YAML 1.2 公开语法约定 | 自带 YAML 子集解析器；已装 PyYAML 时优先用它，两者结果做过一致性交叉校验 |
| `labbridge_auditlog.py` | **零** | 文档 05 第六/七章 | 哈希链审计日志；未基于任何开源日志组件改造 |
| `labbridge_astm.py` | **零** | ASTM E1381 / E1394 公开协议规范 | **替代** `labmcp-astm-lis`（Apache-2.0，★20 早期项目）作为默认接收端 |
| `labbridge_deid.py` | **零** | 文档 02 / 05 | 结构化字段脱敏；Presidio 降级为可选增强 |
| `labbridge_screen.py` | **零** | 文档 04 / 07 | 三条审核规则 + 熔断检测 |
| `labbridge_ocr.py` | **零**（OCR 引擎可选） | 文档 04 / 05 / 07 | 后端适配层，不含任何 OCR 引擎代码 |
| `labbridge_evidence.py` | **零** | 文档 02 / 07 / 08 | 证据包、资产包、验收断言、CAPA |
| `labbridge_gate.py` | **零** | 文档 02 / 05 / 06 | 红线自检、阶段门、审批门 |
| `labbridge_demo.py` | **零** | 文档 04 | 端到端编排器，不引入 langgraph / crewAI 等框架 |

> 为什么坚持零依赖：Demo 要能跑在乡镇卫生院一台没有 pip 环境的普通电脑上，
> 且要与「业务资产解耦、可离线交付」的诉求一致（文档 02 目标 4、文档 08 第四章）。

## 六、声明

本项目中 `labbridge_mcp.py`、`labbridge_docparse.py`、`labbridge_report.py`
及上表全部新增模块，均为**依据公开标准与协议规范独立编写**，
未复制任何 source-available 或许可不明项目的代码。
各文件头部均标注了 Provenance（来源说明），便于审计追溯。

Apache-2.0 与 BSD-3-Clause 组件要求在分发时保留本通知文件；MIT 组件要求保留版权声明。
