# 11 · DEMO 封包说明

> 项目代号：LabBridge（面向二甲及乡镇卫生院的检验数据桥接）
> 文档集版本：V4.2 ｜ 编制日期：2026-10-30
> 对应封包：`LabBridgeV4`

## 一、封包构成总览

| 项 | 数量 | 说明 |
| --- | --- | --- |
| 独立 EXE | 3 个 | `LabBridgeV2.exe`（主程序）、`LabBridge_PDCA.exe`（PDCA 工具集）、`LabBridge_NHANES.exe`（真实数据回放） |
| 源码模块 | 15 个 + 主程序 | `app/code/labbridge_*.py` 共 7085 行；`app/labbridge_v2_app.py` 3230 行 |
| 受控配置 | 8 个 + `SHA256SUMS` | `app/config/` 下 5 个 yaml、2 个 csv，另加规则表一份；2026-10-30 校验 0 失配 |
| 打包配置 | 3 份 | `LabBridgeV2.spec`、`LabBridge_PDCA.spec`、`LabBridge_NHANES.spec` |
| 验收脚本 | 3 份 | `test_v240.py`（46 项）、`test_gui_v240.py`（11 页签）、`test_cloudpanel.py`（22 项） |
| 交付文档 | 2 份 | `部署与使用指南.md`、`真实数据测试报告_NHANES血常规.md` |

#### 产物体积

| 产物 | 体积 |
| --- | --- |
| `LabBridgeV2.exe` | 2,489,689 B（约 2.4 MB） |
| `LabBridge_PDCA.exe` | 8,694,391 B（约 8.3 MB） |
| `LabBridge_NHANES.exe` | 8,694,202 B（约 8.3 MB） |
| `dist/LabBridgeV2/` 整包（含 `_internal` 26 MB） | 45 MB |
| 交付包总计 | 62 MB |

## 二、目录结构

```
LabBridgeV4_交付封包_2026-10-30/
├── README.md                       交付总入口（先看这个）
├── 01_软件封包/
│   ├── app/
│   │   ├── labbridge_v2_app.py     主程序源码（tkinter GUI，3230 行，11 页签）
│   │   ├── code/                   15 个核心模块（均带 --selftest，共 7085 行）
│   │   │   ├── README.md / THIRD_PARTY_NOTICES.md
│   │   ├── config/                 受控规则文件 8 个 + SHA256SUMS
│   │   ├── *.spec                  3 份 PyInstaller 打包配置
│   │   ├── test_*.py               3 份验收脚本
│   │   └── dist/
│   │       ├── LabBridgeV2/        ★ 主程序包（双击 LabBridgeV2.exe 运行）
│   │       │   ├── LabBridgeV2.exe / LabBridge_PDCA.exe / LabBridge_NHANES.exe
│   │       │   ├── config/         受控配置副本（运行时读取）
│   │       │   └── _internal/      Python 运行时（26 MB）
│   │       ├── LabBridge_PDCA.exe     PDCA 独立封包（可单独分发）
│   │       └── LabBridge_NHANES.exe   数据回放独立封包
│   ├── 部署与使用指南.md
│   ├── 真实数据测试报告_NHANES血常规.md
│   └── 交付产物_SHA256.txt         5 个 EXE 路径的 SHA-256 完整性清单
├── 02_立项文档/                    本文档集（00–12 共 13 份，V4.2）
└── 03_验收审计/
    ├── V4封包验收报告_2026-10-30.md      本次重构建的实测验收记录
```

## 三、构建方法

#### 3.1 构建环境

| 项 | 值 |
| --- | --- |
| 操作系统 | Windows（Git Bash 构建） |
| Python | 3.14（原生 `python` 为 3.13 且无 PyInstaller，须显式用 `py -3.14`） |
| PyInstaller | 6.22.3 |
| 编码 | 须设 `PYTHONUTF8=1`，否则中文输出乱码 |

#### 3.2 构建命令

```
cd 01_软件封包/app && export PYTHONUTF8=1

# 1) PDCA 工具集
py -3.14 -m PyInstaller LabBridge_PDCA.spec --noconfirm --distpath ./dist --workpath ./build_tmp

# 2) NHANES 数据回放
py -3.14 -m PyInstaller LabBridge_NHANES.spec --noconfirm --distpath ./dist --workpath ./build_tmp2

# 3) 主程序（onedir 模式）
py -3.14 -m PyInstaller LabBridgeV2.spec --noconfirm --distpath ./dist --workpath ./build_tmp3

# 4) 组装（两个子 EXE + 受控配置进主包）
cp dist/LabBridge_PDCA.exe   dist/LabBridgeV2/
cp dist/LabBridge_NHANES.exe dist/LabBridgeV2/
cp -r config                 dist/LabBridgeV2/
```

#### 3.3 出包前四项检查

| # | 检查项 | 命令 | 期望 |
| --- | --- | --- | --- |
| 1 | 15 模块自检全通过 | 见第五章 | 15/15 PASS |
| 2 | 受控配置零失配 | `cd app/config && sha256sum -c SHA256SUMS` | 全部 OK |
| 3 | 运行时数据零残留 | `find . -name v2_data` | 无输出 |
| 4 | 构建临时目录已清理 | `ls app \ | grep build_tmp` | 无输出 |

## 四、运行手册

#### 4.1 主程序

双击 `01_软件封包/app/dist/LabBridgeV2/LabBridgeV2.exe`（窗口程序，单实例保护：已运行时再次双击会提示而非开新窗口）。如遇"无反应"，先在任务管理器结束旧 `LabBridgeV2.exe` 进程。

PDCA 工具随主程序内置，也可单独运行：

```
dist/LabBridgeV2/LabBridge_PDCA.exe --selftest
```

#### 4.2 登录账户（DEMO 四级权限，可反查 `labbridge_v2_app.py` 第 266–271 行）

| 账户名 | 密码 | 层级 | 管理范围 |
| --- | --- | --- | --- |
| 工程师 | 1111 | L1（最高） | 全域（系统维护、配置、排障） |
| 主任 | 3333 | L2 | 科室级，可终审高风险结论 |
| 组长 | 2222 | L3 | 组级，可复核 |
| 检验员 | 4444 | L4 | 仅本人业务范围 |

规则：`ROLE_LEVEL = {"engineer":1, "director":2, "leader":3, "technician":4}`；Ln 可管理同级及以下（数字更大）账户；低层级不可反向管理高层级；不可删除当前登录账户。

#### 4.3 GUI 页面（11 个）

登录、主页、API 接口（4 个开关）、人员管理、检验数据结果、记录管理、日志溯源、风险热力图、PDCA 工具、敏感信息查看、云端配置、证据包。

其中 API 接口页的 4 个开关（`astm_ingest` / `ocr_extract` / `lis_writeback` / `cloud_llm`）默认全关，开启需走审批四要素并写审计日志——这是 02 号文档红线的直接落点。

#### 4.4 独立工具用法

```
# 全模块自检（15 个，务必显式用 3.14）
cd app/code && export PYTHONUTF8=1
for m in config auditlog astm deid screen gate ocr evidence demo mcp docparse report pdca nhanes apibridge; do
    py -3.14 labbridge_$m.py --selftest
done

# MCP server：stdio 服务运行
py -3.14 labbridge_mcp.py

# NHANES 真实数据回放
LabBridge_NHANES.exe --selftest
```

## 五、自检结论

| 验收项 | 结果 |
| --- | --- |
| 15 模块 `--selftest` | 15/15 PASS |
| `test_v240.py` 整改验收 | 46/46 PASS |
| `test_gui_v240.py` GUI 构建冒烟 | 11/11 页签构建通过 |
| `test_cloudpanel.py` 云端配置接口一致性 | 22 PASS / 0 FAIL |
| PDCA 36 工具（`LabBridge_PDCA.exe --selftest`） | 36/36 通过，0 失败 |
| 受控配置 `SHA256SUMS` 校验 | 8 个条目，0 失配 |
| 产物入口字节码 vs 源码编译 | 一致（3002 B，逐字节相同） |
| PYZ 内 7 个内置模块字节码 | 逐个一致 |
| NHANES EXE 可用性 | `--help` 正常，独立回放通过 |

> 完整逐条记录见 `03_验收审计/V4封包验收报告_2026-10-30.md`。

## 六、NHANES 真实数据回放

与合成数据不同，`LabBridge_NHANES.exe` 灌入的是美国 CDC 公开发布的 NHANES CBC_L 血常规数据（August 2021–August 2023 周期），走 SAS XPORT v5 格式解析，链路完整：解析 → 脱敏 → 规则标记 → 断言 → 证据包。

这条的意义在于：轨道最前端是真实数据而非合成数据，证明链路不是只为合成数据特调的。同时它又不触碰任何患者隐私——数据是公开发布的。详细报告见 `01_软件封包/真实数据测试报告_NHANES血常规.md`。

## 七、诚实边界与运行时数据说明

#### 7.1 运行时数据零残留

| 约束 | 原因 | 落实方式 |
| --- | --- | --- |
| 交付包不得携带 `v2_data/` | V3 缺陷 N-01/N-03/R-01：曾将运行期日志与账户数据打进交付物 | 每次出包前 `find . -name v2_data` 复检，V4 已确认无残留 |
| 证据包须含受控配置副本 | 第三方须能自证「当时的阈值是多少、谁重签过配置」 | `EvidencePack.build()` 自动副本化 8 个受控文件 |
| 构建临时目录须清理 | `build_tmp*` 会污染交付目录且暴露构建路径 | 出包前检查第 4 项 |

#### 7.2 Demo 的能力边界

| 边界 | 说明 |
| --- | --- |
| Demo ≠ 生产上线系统 | 红线 4。Demo 结论可作为正式项目决策依据，但 Demo 本身不等同于生产级上线系统 |
| 不得据此扩容 | 红线 5。扩大范围须重新独立立项、新建 POC |
| 默认口令须更换 | 1111/2222/3333/4444 为 DEMO 口令，部署即须改 |
| 危急值阈值是演示值 | 正式上线前须由检验科按本院方法学签署（对应 R-07、4.1 节 warning 字段） |
| OCR 准确率未达宣称 | 未做实机手写 / 折痕 / 模糊场景实测（07 号 R-07），该能力尚未达标，演示时按「预填 + 人工确认」的半自动模式说明 |
| NHANES 为公开真实数据 | 不等于院内私有数据实测通过 |

## 八、交付完整性核验

```
# 校验 5 个 EXE 是否被替换
cd 交付包根/01_软件封包
sha256sum -c 交付产物_SHA256.txt

# 校验受控配置是否被篡改
cd app/config && sha256sum -c SHA256SUMS
```
