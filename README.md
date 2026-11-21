# QuantumultX-Personal

## 上游 Rewrite 监控

监控器每天 02:17 UTC 运行，也可在 GitHub Actions 手动触发。只有本仓库的 `main` 工作流会更新 [Issue #1](https://github.com/JachinGuan/QuantumultX-Personal/issues/1)。来源及类型见 `upstream/sources.json`，检查程序位于 `scripts/check_upstream.py`。

下载要求 HTTP 200、明确允许的 HTTPS 地址和媒体类型、最多 2 MiB 的 UTF-8 文本，以及相应的 Rewrite 或 JavaScript 基本结构。每次跳转都检查目标。HTML、验证码和 Cloudflare 挑战页会作为异常报告。下载或验证失败时保留原基线。不同 URL 返回相同哈希时会提示进一步排查；重复本身无法说明内容是否恶意。

Issue #1 保持原有基线标记，存储最近的有效哈希和静态特征。旧版只有哈希的记录在首次通过验证时补充特征并保留原始哈希。该次报告列出观察到的特征，并说明历史特征不可比较。缺失或损坏的状态会使检查失败，避免重置基线。成功检测到的变更也会写入 Issue 评论。

静态报告关注 MITM hostname 的增删、可能的范围扩大、远程脚本依赖、可能的网络目的地、敏感信息访问、动态加载、混淆和 Rewrite 修改行为。网络目的地和敏感信息访问为文本线索，动态计算的域名和其他间接行为可能漏检。报告只展示依赖域名和 URL 指纹，避免暴露路径和查询参数。每类特征最多比较 12 项，超出时报告会提示比较不完整。静态检查既不执行下载内容，也不递归获取其依赖。任何风险等级都不构成安全认证。项目的监控工作流只更新 Issue，无需仓库写权限，也不发布 Rewrite。

### 四个重复哈希的排查结果

2026-11-20 实测，BiliBiliAdsLite、StartUpAds、ZhiHu、XiaoHongShu 四个 URL 均返回 HTTP 302 并指向 `https://ddgksf2013.top/`。首页返回 HTTP 200 和 `text/html`，其 SHA-256 为 `5e5b8cbb472625f81baecd3f9a550d4f0ba75a1e5d4dff2c131799a6c0dc4bfd`，与 Issue #1 的四条旧记录一致。监控器会拒绝此跳转，并继续保留原始记录以供排查。

### 本地验证

需要 Python 3.10 或更高版本，仅使用标准库。在仓库根目录运行：

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_upstream.py --dry-run
```

可在试运行时追加 `--baseline /path/to/issue-body.md`，用保存的 Issue 正文验证迁移或比较结果。试运行只读取本地输入和来源 URL，并在标准输出显示报告，不调用 GitHub Issue API。
