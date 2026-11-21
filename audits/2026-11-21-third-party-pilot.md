# 首个第三方 Rewrite 接管可行性

对应 Issue #11，基线为合并 PR #10 的 `main`（`e570a4e`）。2026-11-21 UTC 核对源仓库、GitHub 许可证接口、固定版本响应及脚本静态扫描。筛选只考虑 `upstream/sources.json` 所列来源。没有读取客户端配置，各候选在用户 QX 中的实际启用状态均未知。下载内容未执行，也没有收入仓库。[Issue #11](https://github.com/JachinGuan/QuantumultX-Personal/issues/11)

**结论：本轮没有合格候选，不进入发布阶段。** 三个优先候选均可下载，静态依赖闭包均为入口和一个 JavaScript。没有足以确认全套再托管许可及真实 QX 兼容性的证据。ReleaseCheck 仍是诊断规则。仓库现有发布策略拒绝无专用策略的来源，并拒绝带脚本依赖的快照。

## 优先候选

| 模块 | QX 行为和风险 | 许可和结论 |
| --- | --- | --- |
| CaiYunAds | 12 条规则，包含 `reject-200` 和响应体脚本。MITM 为 `ad.cyapi.cn`、`api.caiyunapp.com`、`starplucker.cyapi.cn`、`wrapper.cyapi.cn`。脚本有响应体读写线索，未识别进一步加载。须在隔离 QX 中核对天气、预警、正常响应以及异常时是否能正常回退。 | Rewrite 和 Scripts 许可证接口均为 404。脚本头有转载署名提示，作者主页也有发布限制声明。尚不能确认入口与脚本作为一组从个人仓库再托管的授权范围。不接管。[Rewrite 作者仓库](https://github.com/ddgksf2013/Rewrite) · [作者发布说明](https://github.com/ddgksf2013/ddgksf2013) |
| RedditAds | 1 条响应体重写，MITM 仅 `gql-fed.reddit.com`。脚本有疑似混淆标识符，未识别进一步加载。响应处理分支和实际副作用无法仅凭扫描确认。与 RedditEnhance 重叠的 GraphQL 主机需要做组合测试。 | 与 CaiYunAds 相同，两仓库均无可核实的标准许可证，脚本有署名提示。授权范围和混淆代码行为待核实。不接管。[Scripts 作者仓库](https://github.com/ddgksf2013/Scripts) |
| RedditEnhance | 1 条请求头重写，MITM 为 `gql.reddit.com`、`gql-fed.reddit.com`。脚本移除两个大小写写法的 Reddit 翻译头并设置简体中文翻译值。未识别进一步加载。实际脚本 URL 返回 301 到同一 Gist 的原始文件。须验证 QX 的请求头写回、规则覆盖顺序和 GraphQL 客户端兼容性。 | Gist 归属 RavelloH，仅有 Loon 插件、JS 和 QX snippet。所核实入口与脚本未见明确许可。行为最容易解释，可在取得作者明确授权后优先复核；目前不接管。[原作者 Gist](https://gist.github.com/RavelloH/68ed0626dae69a1ce7c8ad6887087ea1) |

「静态闭包完整」指当前字节中的已识别引用均取回及校验。不能由此保证运行时不存在间接行为，也没有把内容哈希当成作者签名。上述固定版本未取得独立签名证明。GitHub 上可以读取文件与是否可以再分发是两个不同问题。

## 下载证据

以下固定 URL 均实测直接返回 HTTP 200、`text/plain; charset=utf-8`，通过本仓库内容校验。以固定链接检查原始字节，入口中实际引用仍保持原样；两个墨鱼脚本的实际引用是可变 `master`，其观测哈希与 Issue #1 一致。Gist 的实际脚本链接经允许的同资源 301 后得到表中的字节。无 HTML 或验证码页。[现有监控结果](https://github.com/JachinGuan/QuantumultX-Personal/issues/1)

| 文件 | 固定原始地址 | SHA-256 |
| --- | --- | --- |
| CaiYunAds 入口 | [CaiYunAds.conf](https://raw.githubusercontent.com/ddgksf2013/Rewrite/dc3ea2c1fb2db870676b26da24006083eb1d44d3/AdBlock/CaiYunAds.conf) | `8ba68f9affa24bf759d157d1ab88c9920e1ea25b2cfc36720d0966ceb9220842` |
| CaiYunAds 脚本 | [caiyun_json.js](https://raw.githubusercontent.com/ddgksf2013/Scripts/203e38b7b8dd1082ececbd17de3aeb587ac2826c/caiyun_json.js) | `1a165112aac24bf3830fa47b77d223d85beffdeaf91ee96eef05ab9429b36844` |
| RedditAds 入口 | [RedditAds.conf](https://raw.githubusercontent.com/ddgksf2013/Rewrite/dc3ea2c1fb2db870676b26da24006083eb1d44d3/AdBlock/RedditAds.conf) | `15a17fb23d210144cc3530af925fb20116d89cbfbaf96abd9f2a140a8d24f595` |
| RedditAds 脚本 | [reddit.js](https://raw.githubusercontent.com/ddgksf2013/Scripts/203e38b7b8dd1082ececbd17de3aeb587ac2826c/reddit.js) | `9fba62bb23f38607739e135376c88c8276d4f26d7e1cac478ad7467cedd0590e` |
| RedditEnhance 入口 | [main.snippet](https://gist.githubusercontent.com/RavelloH/68ed0626dae69a1ce7c8ad6887087ea1/raw/27339c9c0a2f440055bf11d1c832b7066b5fb49e/main.snippet) | `40a0393b956218e64c53832e1fd17dc93756dacac7218e22e7211bd11d5b11ff` |
| RedditEnhance 脚本 | [main.js](https://gist.githubusercontent.com/RavelloH/68ed0626dae69a1ce7c8ad6887087ea1/raw/c008127260bc4dcd550fcd98285048cf6176f602/main.js) | `1d3ea8c1046be208540795de979fd64d00a2b4573ae8af61f8595dd418e58d47` |

## 其他监控来源

- GoogleRedirect 无脚本，但主机正则边界和许可待核验，仍排除。AmapAds 已由用户停用，按要求排除。四个跳转 HTML 的入口保持冻结。[上轮风险审计](2026-11-21-qx-rewrite.md)
- Spotify 仓库为 MIT，BoxJS 仓库为 GPL-3.0；两者均存在未解析依赖和动态执行线索，不适合作为最小试点。YouTubeAds 的依赖仓库有 Apache-2.0，入口许可仍未知，且脚本有持久化和未知网络目的地线索。WeatherKit 主仓库有 Apache-2.0，但入口包含头部和响应体等动作，发布包有两份 bundle 及敏感数据处理线索，仍须核对打包依赖许可与客户端行为。[Spotify](https://github.com/app2smile/rules) · [BoxJS](https://github.com/chavyleung/scripts) · [YouTube 脚本](https://github.com/Maasea/sgmodule) · [WeatherKit Release](https://github.com/NSRingo/WeatherKit/releases/tag/v3.3.2)

如果以后取得 RedditEnhance 的明确授权，先保留入口与脚本原始字节及来源清单，再单独核验只改写已识别脚本 URL 的效果。比较字段、动作、匹配范围和未改动字节，在真实隔离 QX 中确认请求头、模块独立开关及与 RedditAds 的顺序。只有这些通过，才考虑独立策略、精确批准锁和 Git SHA 固定发布 URL。回滚应核对旧刊载字节并仅恢复该模块原链接，或者单独停用。此次没有实现或执行这些发布步骤。
