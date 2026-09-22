# zoog-sub

ZoogVPN 节点自动抓取 → Cloudflare 优选 → 订阅发布。GitHub Actions 每日 04:00 (UTC+8) 跑一次，结果提交到 `output/`，由 Cloudflare Pages 自动发布。

## 订阅地址

域名二选一：`https://plutox13117.dpdns.org` 或 `https://zoog-vpn.pages.dev`

订阅已加鉴权，必须带 `?token=<TOKEN>`（或请求头 `X-Sub-Token: <TOKEN>`），否则返回 401。

```
https://plutox13117.dpdns.org/zoog.txt?token=<TOKEN>
```

## 两种类型（都塞进主订阅，用节点名标签分类）

| 标签 | 含义 | 条数 | 命名 |
|---|---|---|---|
| `[精简]` | 按**真实出口**去重后 × 5 优选 IP | 40 | 真实出口地，如 `荷兰-nl-xr.zgrelay.com` |
| `[全量]` | **每个节点** × 5 优选 IP | 655 | Zoog 原始国家名，如 `ES - 瓦伦西亚` |
| `[直连]` | 不套 CF 优选（只在 `zoog-direct.txt`） | 131 | 原始地址 |

主订阅 `{p}.txt` 里**两种类型都在**，靠节点名开头的标签区分。客户端可直接过滤：

- Clash / Clash Meta：订阅加 `filter: "[全量]"` 或正则 `^\[精简\]`
- v2rayN / Shadowrocket / 小火箭：搜索框输 `[精简]` 即可筛

## 文件清单

每个运营商一套，`p` = `zoog`(默认) / `t-zoog`(电信) / `u-zoog`(联通) / `m-zoog`(移动)

| 文件 | 内容 | 条数 |
|---|---|---|
| `{p}.txt` | 精简 + 全量（带标签） | 695 |
| `{p}-lite.txt` | 只精简 | 40 |
| `{p}-full.txt` | 只全量 | 655 |
| `{p}-top30.txt` | 前 30 条（精简优先） | 30 |
| `zoog-direct.txt` | 直连兜底 | 131 |
| `vless_links.txt` | 明文链接，便于核对 | — |

四个运营商的优选 IP 池**互不重叠**（已验证两两交集 = 0）。

## 生成逻辑

1. 登录 ZoogVPN App API，AES-256-CBC 生成 `zoog-fp` 指纹头
2. `servers_v2` 拉服务器列表（125 台），逐台 `server_config` 取 VLESS 配置
3. 去重后得到 131 条真实可用节点
4. 从 `vipmc838/cf_best_ip` 取 Cloudflare 最优 IP（默认/电信/联通/移动 分组）
5. **全组合交叉**：节点 × 该运营商端口对应的 5 个优选 IP
   - 全量：131 × 5 = 655
   - 精简：按 `(出口主机, 端口, 传输)` 去重到 8 个真实出口 × 5 = 40
6. 把 address 换成优选 IP，但**保留原主机名做 SNI**（`sni=`），TLS 握手仍走原域名
7. 节点名 = `标签 名称-优选IP-延迟`，例：

```
[全量] ES - 瓦伦西亚-104.18.39.25-8ms
[精简] 荷兰-nl-xr.zgrelay.com-104.18.39.25-8ms
```

## 为什么要分「精简」

131 个节点实际只落在 **6 个出口**上，123 个国家名基本是同一批中继的别名：

| 出口主机 | 被复用的别名数 |
|---|---|
| nl-xr.zgrelay.com | 69 |
| sg2-xr.zgrelay.com | 31 |
| us-xr.zgrelay.com | 22 |
| fr-xr.vkrysk.space | 5 |
| jasaio32sa.site | 3 |
| es1-xr.jassaa.online / staging.gitlab.com | 1 |

所以全量 655 条里有大量等价节点，客户端加载和测速都慢；精简版 40 条就覆盖了全部真实出口。两份都给你，按需取。

> 注：这些出口主机本身也在 Cloudflare 后面，IP 归属查不到真实落地国家，
> 精简列表的国家名取自 Zoog 自己的命名前缀（nl/sg/us/fr/es），未识别的标 `其他`。

## 鉴权

`functions/_middleware.js`（Pages Functions）拦截所有请求，校验环境变量 `SUB_TOKEN`。
未设置 `SUB_TOKEN` 时直接放行。

## 本地运行

```bash
export ZOOG_EMAIL="..." ZOOG_PASSWORD="..."
export ZOOG_OUTPUT=./output
python3 zoog.py
```

抓不到节点时脚本以非 0 退出，不会提交空订阅。
