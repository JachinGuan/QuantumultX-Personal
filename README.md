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
- **Approved** 是操作员通过独立审查明确指定的版本 ID。监控只读批准锁，告警和导出都不会改动它。保留本地历史候选目录即可按哈希恢复当时的文件，日后可通过人工审查的独立变更将批准锁指回相应版本。没有保存快照字节的历史上游版本只能追溯元数据，无法保证重下载。

使用 Python 3.10 或以上。在仓库根目录运行：

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_upstream.py --dry-run
python3 scripts/check_upstream.py --dry-run --baseline /path/to/issue.md --candidate-dir candidates
```

`--dry-run` 不写入 Issue。`--baseline` 可提供保存的 Issue 正文。`--candidate-dir` 仅在试运行时可用，导出 `candidates/<入口>/<版本>/manifest.json` 和按内容哈希命名的 `objects/*.blob`。对象包含未执行的原始字节，需保留全部文件才能离线复核。`--approved-lock` 可显式读取一份操作员维护的 JSON，键为入口名，值为已批准的版本 SHA-256。

### 后续受控发布

批准和正式发布应使用独立流程与权限，并验证清单、依赖闭包及每份对象哈希。发布器须按识别出的语法位置改写入口和传递依赖，使脚本引用指向不可变的受控版本。需保留 QX 指令、参数、顺序和重写语义，在真实 Quantumult X 客户端验证脚本动作、MITM、重定向和依赖加载。未知绑定存在或客户端兼容性未验证时，应继续冻结。当前版本不生成订阅、不改写 URL，也不部署候选或批准版本。

## GoogleRedirect 受控发布试点

当前上游的正则包含未转义的 `www.`，且未限定主机结束位置，可能匹配形似 Google 的其他域名。发布器会拒绝当前快照。请等待上游提供符合下面限定语法的版本，并在审核时核对原始字节。工具不生成替代规则或改写下载内容。

试点只接受下列两条有效指令，可带空行和以 `#` 开头的 ASCII 注释。地址必须是 HTTPS，且主机必须恰好为 `www.google.cn`。任何其他动作、附加配置、脚本引用、额外对象、重定向来源、不完整图或未知依赖均被拒绝。此校验限定语法和范围，真实客户端行为仍需验证。

```text
hostname = www.google.cn
^https:\/\/www\.google\.cn(?:[/?#]|$) url 302 https://www.google.com
```

### 候选、审核与批准

1. 用 `python3 scripts/check_upstream.py --dry-run --candidate-dir candidates` 获取候选。找到 `candidates/GoogleRedirect/<版本>`，并以 `python3 scripts/publish_rewrite.py review <版本> --input-dir candidates` 校验。命令仅输出审核记录，供人工核对内容、完整闭包和哈希。
2. 在独立的批准 PR 中，将整份候选快照复制到 `release-inputs/GoogleRedirect/<版本>/`。保留原始 `manifest.json` 与 `objects/` 的字节。将审核命令输出放入 `manifests/approvals/GoogleRedirect/<版本>.json`，再将 `manifests/approved.json` 的 `GoogleRedirect` 指向该版本。审核者应独立检查快照和审核记录，确认目标域名、规则行为、文件与清单哈希，并人工合并批准 PR。保留旧快照及历史批准记录。
3. 用 GitHub 保护 `main`，要求批准 PR 独立审查，并限制直接推送。先配置 `rewrite-release` 环境，仅允许受保护的 `main` 发布，启用必需审核者与禁止自审（如仓库方案支持）。工作流检查分支保护状态；必需审核者由仓库管理员配置。保护 `rewrite-publications` 分支，禁止强推、删除和旁路写入，允许指定的发布流程推送。

### 部署和回滚

1. 在 GitHub Actions 手动运行 **Controlled Rewrite release**，选择受保护的 `main`，输入完整版本 ID，并勾选发布确认。发布任务读取该次运行固定提交中的批准锁及审核记录，重新验证候选清单和每个文件哈希，使用同一份已验证字节构建产物。
2. 发布任务将产物追加到 `rewrite-publications`，输出带提交 SHA 与版本 ID 的不可变 URL。以运行摘要中的 URL 为准，不使用分支名作为订阅地址。重复版本会失败。PR 检查只运行测试，没有写权限。监控工作流保持原权限。
3. 在单独的测试配置中用真实 Quantumult X 验证规则、MITM 行为和重定向后，再决定是否人工采用。默认订阅和现有链接不会变动。
4. 回滚时，在本地检出旧发布提交。用当前受信任的仓库检出运行 `python3 scripts/publish_rewrite.py verify-rollback <旧版本> --output /path/to/old-checkout/published`。校验匹配当前保留的历史审核记录、完整旧快照、旧发布凭据及产物。通过后复用原先的 SHA 固定 URL。回滚不覆盖旧文件，也不自动变更客户端。

### 失败恢复

- 缺失快照、哈希不一致、语法拒绝或批准不匹配时，停止发布并重新从可验证的候选开始审查。切勿修改旧记录来匹配新字节。
- 若 Git 推送失败，先检查远程发布分支。已有版本应核对该次提交和凭据，并使用原不可变 URL。远程没有该版本时可重新派发批准过的版本；遇到并发提交也无需强推。
- 只读预览和本地测试使用临时 Fixture，永远不向发布分支写入。真实发布权限、环境审核及客户端兼容性需要管理员和审查者在部署时确认。
