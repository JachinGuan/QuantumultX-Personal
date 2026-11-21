# QuantumultX-Personal

## Rewrite 与依赖监控

GitHub Actions 每天 02:17 UTC 运行，也可手动触发。只有本仓库的 `main` 工作流更新 [Issue #1](https://github.com/JachinGuan/QuantumultX-Personal/issues/1)。正式监控任务使用 `contents: read` 和 `issues: write`。本仓库发往 `main` 的 PR 另有只读任务，运行测试和实网试运行。

- `upstream/sources.json` 定义入口和允许的 Release 下载域名。
- `scripts/check_upstream.py` 保留入口校验、旧 SHA-256 基线和 Issue API。
- `scripts/upstream_transport.py` 验证 URL、DNS、TLS、跳转和下载大小。
- `scripts/upstream_scan.py` 分析 Rewrite 规则和 JavaScript，保存依赖关系及带行号的证据。
- `scripts/upstream_graph.py` 管理递归下载、版本 ID、变化报告和本地候选快照。
- `manifests/approved.json` 由人工维护，记录明确批准的入口版本，初始为空。
- 本地 `candidates/` 可通过命令生成，已加入 Git 忽略规则。正式发布目录留到实现发布流程时建立。

### 监控与安全限制

Rewrite 分析支持 `url`、`url-and-header` 的 `script-*` 动作，以及 `script-path=` 引用。JavaScript 使用静态词法线索识别字面量模块引用、`require`、`importScripts`、Worker、常见脚本加载调用和显式下载脚本的请求。相对 JavaScript 模块地址按脚本最终地址解析。计算得出的地址、裸模块名、本地 QX 路径和不符合 URL 策略的引用会标记为未知。检测到循环、解析不完整或部分下载失败时，候选继续冻结。

下载只使用 HTTPS 443 和直接出站连接，忽略代理设置。每次跳转前检查 URL、跨域策略和 DNS，拒绝私有、环回、链路本地、特殊地址及已知云基础设施地址。连接固定到已检查的公开 IPv4，再用原域名验证 TLS。IPv6-only、含凭据或查询参数的上游地址、未明确允许的跨域跳转会被拒绝。显式配置的 GitHub Release 跳转许可仅扩展到同仓库的版本化 Release 依赖。临时签名只用于下载，保存的最终 URL 去掉该临时查询参数。单文件上限为 2 MiB，总计 24 MiB、48 次唯一资源尝试、150 秒。每次下载最多 12 秒、4 次跳转；每个入口最多记录 18 个文件、160 条依赖边，最多递归 3 层。

Issue 正文保留原 `QX_STATE` 块，另存压缩的依赖状态。旧基线会原样读取；缺少历史依赖扫描时报告首次观察。最近观察和最后完整依赖图分别保留。下载失败、动态引用、循环或扫描截断都不能替换完整基线，也不能进入批准流程。Issue 先提交基线和待发评论，随后发送带去重标识的评论；中断后下次运行补发。若状态超过 Issue 容量或状态损坏，程序报错并保留旧状态。重复哈希用于排查响应来源。

报告使用文件域名、文件名、哈希、行号和经过限制的证据标签。它识别敏感请求头、账号和令牌、存储操作、可能的网络目的地、动态执行和请求或响应修改线索。匹配到关键词或同一文件含有网络请求和敏感访问，均不足以证明外传。扫描可能漏掉混淆、间接调用、运行时模板及未覆盖的语法，也可能误报。每文件最多保留 48 条引用和 48 条证据，报告中的证据增删各最多显示 12 条。达到限制时需要人工审核。工作流不会执行下载内容或改写引用。

2026-11-20 实测，BiliBiliAdsLite、StartUpAds、ZhiHu、XiaoHongShu 均跳转至同一个 HTML 首页，并产生 Issue #1 记录的相同旧哈希。监控会拦截该跳转，保留旧哈希。

### 版本与本地验证

- **Upstream** 是本轮观察到的资源与依赖图。每份有效资源独立记录原始和最终 URL、媒体类型、SHA-256，检查时间保存在快照上。
- **Candidate** 是由入口内容、依赖内容、关系和问题记录共同标识的冻结快照。入口不变时，依赖变化仍会产生新的版本 ID。候选快照只通过本地显式导出落盘，Actions 仅保留 Issue 中的元数据和报告。
- **Approved** 是维护者人工复核后明确指定的版本 ID。监控只读批准锁，告警和导出都不会改动它。保留本地历史候选目录即可按哈希恢复当时的文件，日后可通过人工审查的独立变更将批准锁指回相应版本。没有保存快照字节的历史上游版本只能追溯元数据，无法保证重下载。

使用 Python 3.10 或以上。在仓库根目录运行：

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_upstream.py --dry-run
python3 scripts/check_upstream.py --dry-run --baseline /path/to/issue.md --candidate-dir candidates
```

`--dry-run` 不写入 Issue。`--baseline` 可提供保存的 Issue 正文。`--candidate-dir` 仅在试运行时可用，导出 `candidates/<入口>/<版本>/manifest.json` 和按内容哈希命名的 `objects/*.blob`。对象包含未执行的原始字节，需保留全部文件才能离线复核。`--approved-lock` 可显式读取一份操作员维护的 JSON，键为入口名，值为版本 SHA-256 或包含 `version`、`manifest_sha256` 的对象。旧格式仅供监控显示，试点发布要求绑定清单的对象格式。

### 后续受控发布

批准和正式发布应使用独立流程与权限，并验证清单、依赖闭包及每份对象哈希。发布器须按识别出的语法位置改写入口和传递依赖，使脚本引用指向不可变的受控版本。需保留 QX 指令、参数、顺序和重写语义，在真实 Quantumult X 客户端验证脚本动作、MITM、重定向和依赖加载。未知绑定存在或客户端兼容性未验证时，应继续冻结。当前版本不生成订阅、不改写 URL，也不部署候选或批准版本。

## 模块级管理

`upstream/sources.json` 定义上游下载地址和资源类型，`upstream/modules.json` 按模块 ID 记录管理状态。每个来源独立比较快照和依赖图。共享依赖可以复用一次下载结果，每个引用该依赖的入口仍分别保留变化记录。

| 字段 | 含义 |
| --- | --- |
| `monitor_enabled` | 是否下载并监控该来源。暂停时保留 Issue 入口基线及历史依赖图。 |
| `client_enabled` | 用户报告的 QX 本地开关，`null` 表示未知。开关记录需注明用户来源。仓库不会读取、同步或修改本地配置。 |
| `managed` | 是否由仓库接管发布。还必须有经审查并已实现的专用发布校验策略。 |
| `update_policy` | `review` 允许进入人工审核，`frozen` 禁止发布新版本。冻结不阻止监控或校验已保存的历史版本。 |
| `risk_status` | `normal` 正常、`watch` 待观察、`compatibility_concern` 有兼容性疑虑。 |

**高德去广告（AmapAds）**：用户报告无线 CarPlay 导航时曾偶发从路线导航退回巡航。用户已在 QX 停用该模块，停用后暂未复现。因问题偶发，因果尚未证实。仓库状态为继续监控、冻结更新、暂不接管。保持当前稳定配置。若日后决定排查，仅在停车或安全的独立测试条件下单独比较该模块的关闭状态和已核验版本，记录 QX、系统和应用版本及是否复现即可。勿收集或上传路线、定位、证书、私有订阅或含凭据的日志。若复现，关闭该模块或恢复先前已验证的独立链接；其余模块无需切换。

- **新增或暂停监控**：在两个清单用同一个模块 ID 登记。仅监控时设 `managed: false`，客户端状态设 `null`，除非用户明确报告。暂停或移除时先将 `monitor_enabled` 设为 `false`；移除来源后保留登记及历史审批材料以便追溯。
- **独立采用与冻结**：只有 ReleaseCheck 已有发布校验策略。其他模块在另行审核来源、许可、依赖闭包和兼容性后，才可添加专用策略并接管。受管模块分别批准固定版本与清单哈希，派发时填写单个模块 ID 与版本。流水线仅追加 `published/<模块>/<版本>/<模块>.conf`，发布 URL 还固定到 Git 提交。按模块各自作为 QX 的一个 Rewrite 远程项，使用原生开关独立启停。冻结时将该模块设为 `frozen`，已有链接仍可使用。
- **独立回滚**：保留旧提交 URL 和审核快照，从受信任的仓库检出运行 `python3 scripts/publish_rewrite.py verify-rollback <旧版本> --module <模块> --output /path/to/old-checkout/published`。校验后仅在测试配置中替换该模块原链接。没有可信旧版时，可在 QX 中只关闭该模块。

## ReleaseCheck 受控发布试点

仓库没有客户端的启用列表。现有监控来源不等于客户端已启用规则。2026-11-21 实测，GoogleRedirect 原文件 HTTP 200、无跳转、`text/plain`，SHA-256 为 `f759ce585a197719178cfa5fe2b48c105696c3d2cb1214d09522181233105f97`。它声明 MITM `www.google.cn` 并尝试 302 到 Google，但正则的 `www.` 未转义，也缺少主机边界。GitHub 许可证接口返回 404，无法确认再托管许可，因此继续原样监控。

`pilot/ReleaseCheck.conf` 是仓库自有诊断规则，适用本仓库 Apache-2.0 许可证。它仅匹配 `https://example.com/qx-release-check` 诊断路径，返回 302 至 `https://example.org/`。MITM 仅为 `example.com`，没有 JavaScript 或动态依赖。请在独立 QX 测试配置中验证。候选从固定 Git 提交的原始 HTTPS 地址下载，拒绝跳转、字节不符、附加规则和不完整依赖图。它与 GoogleRedirect 是不同规则。

### iPad 操作

1. 功能 PR 审阅完成并合并后，在 **Actions → Prepare ReleaseCheck review materials → Run workflow** 选择 `main`。打开运行摘要查看静态风险，`release-check-review` 提供候选字节和审核记录。准备流程只有仓库读取权限。
2. 将运行链接交给有推送权限的助手。助手可通过 `gh run download <运行 ID> -n release-check-review` 取得材料。如果下载存储被代理拦截，助手可从同次运行日志里的 `QX_REVIEW_BUNDLE` 取得相同材料并重新校验。核对后另开批准 PR，只提交 `release-inputs/` 和历史审核记录。iPad 无需上传。你核对差异后，在该批准 PR 分支用 GitHub 网页编辑 `manifests/approved.json`，填入 `ReleaseCheck` 的 `version` 和 `manifest_sha256`。确认后由你手动合并批准 PR。
3. 在 **Actions → Controlled Rewrite release → Run workflow** 选择 `main`，填写模块 ID（当前为 `ReleaseCheck`）和已批准的完整版本 ID 并确认。只有所有者能派发或重跑。发布会校验批准锁、候选路径、清单、文件哈希和固定来源字节。它只向发布分支追加版本，拒绝覆盖。推送后从固定发布提交的 raw URL 下载并比对，成功后摘要才显示可用链接。

### 个人仓库权限

默认要求生效的 rulesets。`main` 通过 PR 更新，审批人数可设为 0。为 `main` 和 `rewrite-publications` 禁止强推及删除。2026-11-21 查询时，`main` 未受保护，有效规则集为空，发布分支未查到；Actions 管理权限接口对当前凭据返回 403。

个人公开仓库确实只有你能写入时，可在 **Settings → Secrets and variables → Actions → Variables → New repository variable** 显式设置 `QX_RELEASE_POLICY=personal-owner`。该模式仍要求所有者派发、精确批准、验证来源以及非强制追加推送，但没有服务端防改历史的保障。若有其他写入者，请使用 rulesets。GitHub 拒绝写入时工作流会失败，不会更换令牌或跳过校验。所有者账号失陷不在此模型的保障范围内。

### 验证与回滚

真实 runner 从 PR 提交下载原始诊断规则，校验与 checkout 字节一致并保存只读审核材料。测试在 runner 的本地临时 Git 远端模拟人工批准、追加、重复发布拒绝、按 SHA 取回和回滚。真实发布分支写权限、发布后的 raw URL 和 QX 客户端仍需首次手动发布时验证。

回滚时保留旧快照、审核记录和发布提交。检出旧提交后可运行 `python3 scripts/publish_rewrite.py verify-rollback <旧版本> --output /path/to/old-checkout/published`，核验通过后复用原 SHA 固定链接。推送失败或 raw 校验失败时，先检查远程是否已有该版本；已有则核对回执及内容，禁止重写。静态检查不保证安全或客户端兼容。
