# zoog-sub

ZoogVPN 节点自动抓取 → Cloudflare 优选 → 订阅发布。GitHub Actions 每日 04:00 (UTC+8) 跑一次，结果提交到 `output/`，由 Cloudflare Pages 自动发布。

## 订阅地址

域名二选一：`https://plutox13117.dpdns.org` 或 `https://zoog-vpn.pages.dev`

订阅加了鉴权，必须带 `?token=<TOKEN>`（或请求头 `X-Sub-Token: <TOKEN>`），否则返回 401。

```
https://plutox13117.dpdns.org/zoog.txt?token=<TOKEN>
```

## 终极版：三种类型全部放进主订阅，用标签分类

主订阅 `{p}.txt` 一个文件里同时含 **826 条**，分三类，靠节点名开头的标签区分：

| 标签 | 类型 | 条数 | 分配规则 | 什么时候用 |
|---|---|---|---|---|
| `[精简]` | 精简 | **40** | 按真实出口去重（131 → 8 个出口），每个出口 × 5 个优选 IP | 想要最少节点、最快测速 |
| `[轮流]` | 轮流交换 | **131** | 每个节点轮流分 1 个优选 IP，IP 均匀轮转（实测 26/26/26/26/26） | 想要 1 节点 1 IP 的干净列表 |
| `[全交叉]` | 全组合交叉 | **655** | 每个节点 × 每个优选 IP 全组合（131 × 5） | 想要全覆盖、让客户端自己挑 |

命名示例：

```
[精简]   新加坡-sg2-xr.zgrelay.com-172.64.53.238-1ms
[轮流]   新西兰 - 奥克兰-172.64.53.238-1ms
[全交叉] 新西兰 - 奥克兰-172.64.53.238-1ms
```

- `[精简]` 用**真实出口域名**命名（不套 Zoog 的虚名国家）
- `[轮流]` / `[全交叉]` 保留 ZoogVPN 原始国家名
- 三者都是 `原主机名做 SNI`，只换 address 为 CF 优选 IP

## 文件清单

每个运营商一套，`p` = `zoog`(默认) / `t-zoog`(电信) / `u-zoog`(联通) / `m-zoog`(移动)

| 文件 | 内容 | 条数 |
|---|---|---|
| `{p}.txt` | **精简 + 轮流 + 全交叉**（都带标签） | **826** |
| `{p}-lite.txt` | 只 `[精简]` | 40 |
| `{p}-rr.txt` | 只 `[轮流]` | 131 |
| `{p}-full.txt` | 只 `[全交叉]` | 655 |
| `{p}-top30.txt` | 前 30 条（精简 → 轮流 → 全交叉 顺序） | 30 |
| `zoog-direct.txt` | 直连兜底，不套优选，标签 `[直连]` | 131 |
| `vless_links.txt` | 明文链接，便于核对 | 826 |

四个运营商的优选 IP 池**互不重叠**（已验证两两交集 = 0）。

## 客户端怎么按标签分类

- **Clash / Clash Meta**：`proxy-groups` 里用 `filter` 正则
  ```yaml
  - name: "Zoog-精简"
    type: select
    filter: "\[精简\]"
  - name: "Zoog-轮流"
    type: select
    filter: "\[轮流\]"
  - name: "Zoog-全交叉"
    type: select
    filter: "\[全交叉\]"
  ```
- **v2rayN / Shadowrocket / 小火箭**：搜索框输 `[精简]`、`[轮流]`、`[全交叉]` 即可筛
- 不想过滤就直接订阅分流文件：`.../zoog-lite.txt?token=...`

## 生成逻辑

1. 登录 ZoogVPN App API，AES-256-CBC 生成 `zoog-fp` 指纹头
2. `servers_v2` 拉服务器列表（125 台），逐台 `server_config` 取 VLESS 配置
3. 去重后得到 131 条真实可用节点
4. 从 `vipmc838/cf_best_ip` 取 Cloudflare 最优 IP（默认/电信/联通/移动 分组，共 30 个）
5. 每个运营商按端口实测延迟，取该端口最快的 5 个作为优选池
6. 三种分配方式各生成一份，打标签后合并进主订阅
7. address 换成优选 IP，**保留原主机名做 SNI**（`sni=`），TLS 握手仍走原域名

## 为什么还要分「精简」

131 个节点实际只落在 **6 个出口**上，123 个国家名基本是同一批中继的别名：

| 出口主机 | 被复用的别名数 |
|---|---|
| nl-xr.zgrelay.com | 69 |
| sg2-xr.zgrelay.com | 31 |
| us-xr.zgrelay.com | 22 |
| fr-xr.vkrysk.space | 5 |
| jasaio32sa.site | 3 |
| es1-xr.jassaa.online | 1 |

> 注：这些出口主机本身也在 Cloudflare 后面，IP 归属查不到真实落地国家，
> 精简列表的国家名取自 Zoog 自己的命名前缀（nl/sg/us/fr/es），识别不了的标 `其他`。

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
