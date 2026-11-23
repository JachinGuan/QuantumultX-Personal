# QX 固定版本候选清单

清单依据 Issue #1 在北京时间 2026-11-22 17:44:37 的观测，2026-11-23 复核 RedditEnhance 固定来源。四个失效地址的重复历史哈希属于首页响应。

客户端开关只反映用户报告。静态闭包完整不等于安全或客户端兼容。

| 模块 | 上游 / 历史 SHA-256 | 上次入口观测 | 静态闭包 | 许可 | 固定状态 | 客户端 |
| --- | --- | --- | --- | --- | --- | --- |
| RedditAds | [原地址](https://raw.githubusercontent.com/ddgksf2013/Rewrite/refs/heads/master/AdBlock/RedditAds.conf) / `15a17fb23d210144cc3530af925fb20116d89cbfbaf96abd9f2a140a8d24f595` | 有有效历史入口 | 完整静态图，1 个依赖 | 未确认再分发许可 | 未完整冻结：仍引用浮动或未知依赖 | 未知 |
| RedditEnhance | [原地址](https://gist.githubusercontent.com/RavelloH/68ed0626dae69a1ce7c8ad6887087ea1/raw/main.snippet) / `40a0393b956218e64c53832e1fd17dc93756dacac7218e22e7211bd11d5b11ff` | 有有效历史入口 | 完整静态图，1 个依赖 | 未确认再分发许可 | 研究样本：固定版本和可解析引用均有证据，许可待核对 | 未知 |
| BiliBiliAdsLite | [原地址](https://ddgksf2013.top/rewrite/BiliBiliAdsLite.conf) / `5e5b8cbb472625f81baecd3f9a550d4f0ba75a1e5d4dff2c131799a6c0dc4bfd` | 失败 | 未知 | 未确认再分发许可 | 上游不可用或跳转首页，保留原地址 | 未知 |
| Spotify | [原地址](https://raw.githubusercontent.com/app2smile/rules/master/module/spotify.conf) / `eec2c8e4004dd0b0b4753369a5bd108f02519e0597bdea64962ccc0d38cc612e` | 有有效历史入口 | 不完整或未知 | 仓库 MIT，打包依赖与再分发范围待核对 | 未完整冻结：静态依赖闭包不完整或未知 | 未知 |
| StartUpAds | [原地址](https://ddgksf2013.top/rewrite/StartUpAds.conf) / `5e5b8cbb472625f81baecd3f9a550d4f0ba75a1e5d4dff2c131799a6c0dc4bfd` | 失败 | 未知 | 未确认再分发许可 | 上游不可用或跳转首页，保留原地址 | 未知 |
| CaiYunAds | [原地址](https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/CaiYunAds.conf) / `8ba68f9affa24bf759d157d1ab88c9920e1ea25b2cfc36720d0966ceb9220842` | 有有效历史入口 | 完整静态图，1 个依赖 | 未确认再分发许可 | 未完整冻结：仍引用浮动或未知依赖 | 未知 |
| ZhiHu | [原地址](https://ddgksf2013.top/scripts/zhihu.ads.js) / `5e5b8cbb472625f81baecd3f9a550d4f0ba75a1e5d4dff2c131799a6c0dc4bfd` | 失败 | 未知 | 未确认再分发许可 | 上游不可用或跳转首页，保留原地址 | 未知 |
| YouTubeAds | [原地址](https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/YoutubeAds.conf) / `480335f6327cd3a8e3c8dab4194bd7783f465dcc6f218a7b32c3aec89782b2b4` | 有有效历史入口 | 完整静态图，1 个依赖 | 脚本仓库 Apache-2.0，入口许可未知 | 未完整冻结：仍引用浮动或未知依赖 | 未知 |
| AmapAds | [原地址](https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/AmapAds.conf) / `d0c1caf909e3e9151ec890eb31bc14dc28b34c49d6c8a1ef42c147cd949564b3` | 有有效历史入口 | 完整静态图，2 个依赖 | 未确认再分发许可 | 未完整冻结：仍引用浮动或未知依赖 | 停用（用户报告） |
| GoogleRedirect | [原地址](https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/Html/General.conf) / `f759ce585a197719178cfa5fe2b48c105696c3d2cb1214d09522181233105f97` | 有有效历史入口 | 完整静态图，0 个依赖 | 未确认再分发许可 | 无与当前基线匹配的已验证固定版本 | 未知 |
| XiaoHongShu | [原地址](https://ddgksf2013.top/rewrite/XiaoHongShuAds.conf) / `5e5b8cbb472625f81baecd3f9a550d4f0ba75a1e5d4dff2c131799a6c0dc4bfd` | 失败 | 未知 | 未确认再分发许可 | 上游不可用或跳转首页，保留原地址 | 未知 |
| BoxJS | [原地址](https://raw.githubusercontent.com/chavyleung/scripts/master/box/rewrite/boxjs.rewrite.quanx.conf) / `39bbc01168931bc67f333468c743b8022d770e240d41b36847bc96a2aa5510f5` | 有有效历史入口 | 不完整或未知 | 仓库 GPL-3.0，分发义务与闭包待核对 | 未完整冻结：静态依赖闭包不完整或未知 | 未知 |
| WeatherKit | [原地址](https://github.com/NSRingo/WeatherKit/releases/latest/download/iRingo.WeatherKit.snippet) / `9a153d575761dda3b25116c751085ec56ad9c312991892cc6d18de58bae89256` | 有有效历史入口 | 完整静态图，2 个依赖 | 仓库 Apache-2.0，发布包内的依赖许可待核对 | 未完整冻结：仍引用浮动或未知依赖 | 未知 |
| ReleaseCheck | 无 | 未监控 | 不适用 | 见仓库现有批准流程 | 无上游监控入口 | 未知 |

## 可手动复制的候选

当前无符合条件的候选。
## RedditEnhance 技术样本

从作者 Gist Git 历史核实入口固定在提交 `50b1b657262d915484bae98d5acc91b6473d0226`，实际引用的脚本固定在更早的提交 `c008127260bc4dcd550fcd98285048cf6176f602`。两者是 Git 提交对象。没有把 Gist 文件 API 提供的 blob ID 当成提交。固定原始地址均实测 HTTP 200、`text/plain`、无跳转。入口 SHA-256 如上表，JS 为 `1d3ea8c1046be208540795de979fd64d00a2b4573ae8af61f8595dd418e58d47`，均与完整监控基线一致。入口仍引用原作者地址，GitHub Gist 正常跳转到同一固定修订的原始脚本。本仓库没有改写或复制规则字节。脚本没有发现更深的静态引用，QX 行为和再分发许可仍待核验。[作者 Gist](https://gist.github.com/RavelloH/68ed0626dae69a1ce7c8ad6887087ea1) · [许可审计 PR](https://github.com/JachinGuan/QuantumultX-Personal/pull/12) · [Issue #1](https://github.com/JachinGuan/QuantumultX-Personal/issues/1)

GitHub raw 分支链接会随分支更新。固定入口的提交不会固定它引用的分支脚本。Release 的 `latest`、普通版本标签和会过期的签名资产地址均不满足本工具的不可变性条件。失效站点继续沿用原来源进行监控。
