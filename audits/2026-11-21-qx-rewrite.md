# Quantumult X Rewrite 风险审计

审计基线为 `main` 提交 `1c79bc3`。监控数据采用 2026-11-21 01:29:40 UTC 的 Issue #1。该次验证了 9/13 个入口和共 21 份文件，另有 4 个入口被拦截。维护元数据及部分 URL 于 2026-11-21 UTC 复核。仓库未保存客户端启用清单，**无法确认任何这 13 项在客户端的启用状态，也无法列出仓库未收录的启用项**。没有读取或收集客户端配置、私有订阅、证书或凭据。[Issue #1](https://github.com/JachinGuan/QuantumultX-Personal/issues/1) · [四个入口的溯源](https://github.com/JachinGuan/QuantumultX-Personal/pull/6)

## 风险分级与处置

- **保留原始链接**适用于现有体验稳定、可维持原样观察的项目。以下意见均针对未来变更和托管决策。
- **建议冻结**指暂停采纳新版本和迁移。只有既有可信快照才能作为可验证的回滚点。旧首页哈希不能作为有效脚本快照。
- **需人工核验**指还需验证语义、客户端或许可。**暂不接管**指证据不足以进入自托管。
- 表中的「图完整」仅指监控器发现的静态引用均已解析、下载和校验。运行时分支、变量构造、混淆和脚本副作用可能未识别。JS 栏表示配置可能交由 Quantumult X 执行的行为，此次监控和审计均只分析文本。

| 入口 | 实际响应、依赖与 MITM | 更新、许可与兼容性 | 风险与处置 |
| --- | --- | --- | --- |
| RedditAds | 200；静态图完整，挂载 `reddit.js` 修改响应体。MITM 为 `gql-fed.reddit.com`。脚本出现疑似混淆标识符。 | 入口文件最后提交 2025-12-12。入口及脚本未确认许可。依赖可随分支更新，响应结构变化可能破坏页面。 | **高**，建议冻结更新，需人工核验。 |
| RedditEnhance | 200；静态图完整，固定 Gist 修订的 `main.js` 由 GitHub Gist 跳转至 Gist 原始文件，读取请求头相关信息。MITM 为 `gql-fed.reddit.com`、`gql.reddit.com`。 | Gist 最近修订 2026-04-27；未看到许可证文件。与 RedditAds 共用一个 MITM 主机，规则顺序、请求头修改及客户端兼容性需实测。 | **中**，暂不接管，需人工核验。 |
| Spotify | 200；3 个脚本通过下载验证，图不完整。请求头和响应体脚本涉及 `*spclient.spotify.com`、`spclient.wg.spotify.com`。发现 `Function`、`eval` 和未知网络目的地线索。 | 入口最后提交 2025-06-27；上游仓库标记 MIT。仍需核对打包代码所含第三方组件和许可、协议版本兼容性及数据流。 | **高**，建议冻结，暂不接管。 |
| CaiYunAds | 200；静态图完整，`caiyun_json.js` 修改响应体，另有 `reject-200`。MITM 为 `ad.cyapi.cn`、`api.caiyunapp.com`、`starplucker.cyapi.cn`、`wrapper.cyapi.cn`。 | 入口最后提交 2025-12-12；入口和脚本许可未知。需验证天气、预警和响应格式兼容性。 | **中**，若已稳定启用则保留原始链接，暂不接管。 |
| YouTubeAds | 200；静态图完整，`youtube.response.js` 修改响应体，存在存储与未知目的地的请求线索，数据流未证实。入口 302 由捕获组构造目标。MITM 为 `*.googlevideo.com`、排除项 `-redirector*.googlevideo.com`、`s.youtube.com`、`www.youtube.com`、`youtubei.googleapis.com`。 | 入口最后提交 2025-04-15；依赖文件最后提交 2026-07-19。脚本仓库标记 Apache-2.0，入口许可未知。需验证泛域名排除规则与播放兼容性。 | **高**，建议冻结更新，需人工核验。 |
| AmapAds | 200；静态图完整，`amap.js` 和 `amdc.js` 涉及响应修改，前者有疑似混淆标识符。MITM 为 `ai.amap.com`、`amap-aos-info-nogw.amap.com`、`center.amap.com`、`m5-zb.amap.com`、`m5.amap.com`。 | 入口最后提交 2025-12-12；入口及脚本许可未确认。需验证导航和搜索请求、各版本回退行为。 | **高**，建议冻结更新，需人工核验。 |
| GoogleRedirect | 200；静态图完整，无 JS，MITM 为 `www.google.cn`。固定 302 目标为 `https://www.google.com`，原正则有未转义点且缺少严格主机边界。 | 入口最后提交 2024-06-01。许可未确认，主机匹配及目标行为需核验。 | **中**，暂不接管。 |
| BoxJS | 200；`chavy.boxjs.js` 通过下载验证，但静态图不完整。发现 `eval` 和未解析的代码加载线索。MITM 为 `*.boxjs.com`、`*.boxjs.net`、`boxjs.com`、`boxjs.net`。 | 入口最后提交 2023-02-08，仓库 2026-10-22 仍有推送，标记 GPL-3.0。自托管前需核验分发义务、动态依赖与存储兼容性。 | **高**，建议冻结，暂不接管。 |
| WeatherKit | Release 经允许的 GitHub 跨域跳转后返回 200；静态图完整，具有请求头、响应体和回显脚本，两个 bundle 出现 Token 和 `unescape` 线索。MITM 为 `weatherkit.apple.com`。 | 监控关联 v3.3.2，发布于 2026-08-29；仓库标记 Apache-2.0，仍须核验 bundle 内第三方声明、Apple API 行为和客户端兼容性。 | **高**，建议冻结更新，需人工核验。 |
| BiliBiliAdsLite | 302 指向 HTML 首页，当前依赖及 MITM 未知。2026-01-14 历史版 MITM 为 `app.bilibili.com`，脚本依赖现为 404。 | 历史入口已删除，现行等价性和许可未知。 | **未知**，建议冻结，暂不接管。 |
| StartUpAds | 302 指向 HTML 首页，当前依赖及 MITM 未知。旧版曾涉及 398 个 MITM 项、28 个脚本地址，无法完整验证。 | 原 2.0 Gist 返回 404，2025-03-31 的旧版不能证明与当前版本等价；许可未知。 | **未知**，建议冻结，暂不接管。 |
| ZhiHu | JavaScript 入口返回 302 指向 HTML 首页，当前脚本及依赖未知。旧原作者 Gist 404；现存开屏脚本仅覆盖 `launch_v2`，示例 MITM 为 `api.zhihu.com`。 | 开屏脚本有转载限制，未确认与原 JS 等价；历史同名 JS 只有注释。 | **未知**，建议冻结，暂不接管。 |
| XiaoHongShu | 302 指向 HTML 首页，当前依赖及 MITM 未知。2025-12-12 历史版使用 `*.xiaohongshu.com`，脚本依赖现为 404。 | 历史入口已删除，现行等价性和许可未知。 | **未知**，建议冻结，暂不接管。 |

维护时间来自 GitHub 文件提交、Gist 修订和 Release 元数据。许可证是仓库级线索，尚未出结论的文件、依赖及再分发义务仍需人工核对。[Rewrite](https://github.com/ddgksf2013/Rewrite) · [Scripts](https://github.com/ddgksf2013/Scripts) · [RedditEnhance Gist](https://gist.github.com/RavelloH/68ed0626dae69a1ce7c8ad6887087ea1) · [Spotify](https://github.com/app2smile/rules) · [YouTube 脚本](https://github.com/Maasea/sgmodule) · [BoxJS](https://github.com/chavyleung/scripts) · [WeatherKit v3.3.2](https://github.com/NSRingo/WeatherKit/releases/tag/v3.3.2)

## 冻结试点与回滚

**优先使用仓库自有的 ReleaseCheck 诊断规则，在独立 QX 测试配置中验证冻结与回滚。** 它是可独立下载的真实 Rewrite，仓库采用 Apache-2.0，仅命中 `example.com/qx-release-check` 的 HTTPS 诊断请求并返回 302 到 `https://example.org/`。MITM 仅为 `example.com`，没有脚本。现有批准快照源提交为 `569736848328353b218f507709413163f5e8bc7c`，版本为 `dc05067119c824b071c8b60ef576c9bffa46b7cdcb0f074e4b05a772b5d49aed`，文件 SHA-256 为 `0991634f1d53fd6aa8902c9d4aae0555207c0f411d61d4b5506ac600a502b09f`。本审计未发现可同时确认已启用、许可清晰及低风险的第三方试点。无依赖的 GoogleRedirect 也因主机边界和许可问题暂不接管。[固定原始规则](https://github.com/JachinGuan/QuantumultX-Personal/blob/569736848328353b218f507709413163f5e8bc7c/pilot/ReleaseCheck.conf) · [既有批准记录](https://github.com/JachinGuan/QuantumultX-Personal/pull/5)

1. 用现有审核器重算清单、版本 ID、入口 SHA-256 和空脚本闭包。由所有者在专用测试配置检查带查询参数的诊断路径、相似路径和主机负例，以及其他 `example.com` 请求是否被重写。记录 QX 版本、网络与 MITM 行为。
2. 在以后授权的发布演练中，核对固定 Git 提交 URL 下载字节与已审快照相同。只在测试配置采用该 URL，并保存原测试链接及完整审核快照。
3. 若体验或哈希异常，在测试配置中移除该试点，或者在本地 `verify-rollback` 校验后恢复此前已审核的固定 URL。首次试点没有旧的发布 URL 时，以移除试点作为回滚。常用客户端配置保持原样。

## 重复验证与审计证据

保存 Issue #1 正文后，在仓库根目录运行 `python3 scripts/check_upstream.py --dry-run --baseline /path/to/issue.md`，使用仓库的 HTTPS 和静态扫描策略获取新观测。用 `python3 -m unittest discover -s tests -v` 验证不完整依赖图和监控失败的状态保护。日常监控更新 Issue，不写批准锁、快照或发布分支。下表记录一次观测，分支及 latest 链接可能已经前移。历史重复 SHA-256 `5e5b8cbb472625f81baecd3f9a550d4f0ba75a1e5d4dff2c131799a6c0dc4bfd` 属于 HTML 首页，四个失败项本轮没有有效入口哈希。

| 入口／文件 | 观测 URL | SHA-256 |
| --- | --- | --- |
| RedditAds | [原始入口](https://raw.githubusercontent.com/ddgksf2013/Rewrite/refs/heads/master/AdBlock/RedditAds.conf) | `15a17fb23d210144cc3530af925fb20116d89cbfbaf96abd9f2a140a8d24f595` |
| ↳ reddit.js | [原始引用](https://raw.githubusercontent.com/ddgksf2013/Scripts/refs/heads/master/reddit.js) | `9fba62bb23f38607739e135376c88c8276d4f26d7e1cac478ad7467cedd0590e` |
| RedditEnhance | [原始入口](https://gist.githubusercontent.com/RavelloH/68ed0626dae69a1ce7c8ad6887087ea1/raw/main.snippet) | `40a0393b956218e64c53832e1fd17dc93756dacac7218e22e7211bd11d5b11ff` |
| ↳ main.js | [原始引用](https://gist.github.com/RavelloH/68ed0626dae69a1ce7c8ad6887087ea1/raw/c008127260bc4dcd550fcd98285048cf6176f602/main.js) | `1d3ea8c1046be208540795de979fd64d00a2b4573ae8af61f8595dd418e58d47` |
| BiliBiliAdsLite | [原始入口](https://ddgksf2013.top/rewrite/BiliBiliAdsLite.conf) | 无有效哈希 |
| Spotify | [原始入口](https://raw.githubusercontent.com/app2smile/rules/master/module/spotify.conf) | `eec2c8e4004dd0b0b4753369a5bd108f02519e0597bdea64962ccc0d38cc612e` |
| ↳ spotify-json.js | [原始引用](https://raw.githubusercontent.com/app2smile/rules/master/js/spotify-json.js) | `41cf1074770cdef3948baa12ff4a8db9045d1cac888714c8b7e69909eb531bc9` |
| ↳ spotify-proto.js | [原始引用](https://raw.githubusercontent.com/app2smile/rules/master/js/spotify-proto.js) | `2e6850e888d092905c766f0bbedc4b4afb9a712330970cc1265105d7fb4995d0` |
| ↳ spotify-qx-header.js | [原始引用](https://raw.githubusercontent.com/app2smile/rules/master/js/spotify-qx-header.js) | `77267bc9bdcc8a2bc8eb1e70fffaeee0fb0c097a076bc9040b6c430acf051f3c` |
| StartUpAds | [原始入口](https://ddgksf2013.top/rewrite/StartUpAds.conf) | 无有效哈希 |
| CaiYunAds | [原始入口](https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/CaiYunAds.conf) | `8ba68f9affa24bf759d157d1ab88c9920e1ea25b2cfc36720d0966ceb9220842` |
| ↳ caiyun_json.js | [原始引用](https://raw.githubusercontent.com/ddgksf2013/Scripts/refs/heads/master/caiyun_json.js) | `1a165112aac24bf3830fa47b77d223d85beffdeaf91ee96eef05ab9429b36844` |
| ZhiHu | [原始入口](https://ddgksf2013.top/scripts/zhihu.ads.js) | 无有效哈希 |
| YouTubeAds | [原始入口](https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/YoutubeAds.conf) | `480335f6327cd3a8e3c8dab4194bd7783f465dcc6f218a7b32c3aec89782b2b4` |
| ↳ youtube.response.js | [原始引用](https://raw.githubusercontent.com/Maasea/sgmodule/refs/heads/master/Script/Youtube/youtube.response.js) | `f98483d5f5017514f82502253c0db5ce2d4ffb7839887aa2cadc22666f5a7f12` |
| AmapAds | [原始入口](https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/AmapAds.conf) | `d0c1caf909e3e9151ec890eb31bc14dc28b34c49d6c8a1ef42c147cd949564b3` |
| ↳ amap.js | [原始引用](https://raw.githubusercontent.com/ddgksf2013/Scripts/refs/heads/master/amap.js) | `936aaaf97cf69b8a5a25ba49303c0470a16ac48851e8bf58080ff9f129ff7c48` |
| ↳ amdc.js | [原始引用](https://raw.githubusercontent.com/ddgksf2013/Scripts/refs/heads/master/amdc.js) | `8217f2150f8d12ae04d2c49b5da0a838e83f4de68b34df71c2da16cc1267898f` |
| GoogleRedirect | [原始入口](https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/Html/General.conf) | `f759ce585a197719178cfa5fe2b48c105696c3d2cb1214d09522181233105f97` |
| XiaoHongShu | [原始入口](https://ddgksf2013.top/rewrite/XiaoHongShuAds.conf) | 无有效哈希 |
| BoxJS | [原始入口](https://raw.githubusercontent.com/chavyleung/scripts/master/box/rewrite/boxjs.rewrite.quanx.conf) | `39bbc01168931bc67f333468c743b8022d770e240d41b36847bc96a2aa5510f5` |
| ↳ chavy.boxjs.js | [原始引用](https://raw.githubusercontent.com/chavyleung/scripts/master/box/chavy.boxjs.js) | `24ab4513d9b210d3921f87660175ddf408f2c4728a01ecb391082e82d8f8ffa6` |
| WeatherKit | [原始入口](https://github.com/NSRingo/WeatherKit/releases/latest/download/iRingo.WeatherKit.snippet) | `9a153d575761dda3b25116c751085ec56ad9c312991892cc6d18de58bae89256` |
| ↳ request.bundle.js | [原始引用](https://github.com/NSRingo/WeatherKit/releases/download/v3.3.2/request.bundle.js) | `da05af299dd2172e1c25a2bff349cdda268114ee7fc43340cc48da29c76ea033` |
| ↳ response.bundle.js | [原始引用](https://github.com/NSRingo/WeatherKit/releases/download/v3.3.2/response.bundle.js) | `ce1db90d77c44fce972db0c2e319845fc1d6a276d41d772c0294882e59d7f999` |
