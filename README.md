# zoog-sub

ZoogVPN 节点自动抓取 → Cloudflare 优选 → 订阅发布。GitHub Actions 每日 04:00 (UTC+8) 跑一次，结果提交到 `output/`，由 Cloudflare Pages 自动发布。

## 订阅地址

域名二选一：`https://plutox13117.dpdns.org` 或 `https://zoog-vpn.pages.dev`

订阅已加鉴权，必须带 `?token=<TOKEN>`（或请求头 `X-Sub-Token: <TOKEN>`），否则返回 401。

| 文件 | 运营商 | 条数 | 说明 |
|---|---|---|---|
| `zoog.txt` | 默认（通用优选） | 655 | 全量：每个节点 × 5 个优选 IP |
| `t-zoog.txt` | 电信 | 655 | 电信专用优选 IP 池 |
| `u-zoog.txt` | 联通 | 655 | 联通专用优选 IP 池 |
| `m-zoog.txt` | 移动 | 655 | 移动专用优选 IP 池 |
| `zoog-top30.txt` 等 | 同上 | 30 | 延迟最低的 30 条 |
| `zoog-direct.txt` | — | 131 | 不套 CF 优选的直连兜底 |

示例：

```
https://plutox13117.dpdns.org/t-zoog.txt?token=<TOKEN>
https://plutox13117.dpdns.org/zoog-top30.txt?token=<TOKEN>
```

## 生成逻辑

1. 登录 ZoogVPN App API，用 AES-256-CBC 生成 `zoog-fp` 指纹头
2. `servers_v2` 拉取服务器列表（125 台），逐台 `server_config` 取 VLESS 配置
3. 去重后得到 131 条真实可用节点
4. 从 `vipmc838/cf_best_ip` 取 Cloudflare 最优 IP（按 默认/电信/联通/移动 分组，共 30 个）
5. **全组合交叉**：每个节点 × 该运营商端口对应的 5 个优选 IP → 131 × 5 = 655
6. 替换 address 为优选 IP，但 **保留原主机名做 SNI**（`sni=`），TLS 握手仍走原域名
7. 节点名后缀带上优选 IP 和延迟，如 `ES - 瓦伦西亚-104.18.39.25-8ms`

四个运营商的 IP 池**互不重叠**（已验证交集为 0）。

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

## 已知情况

131 条节点中，实际出口地址只有 6 个（nl-xr.zgrelay.com / sg2-xr.zgrelay.com / us-xr.zgrelay.com / fr-xr.vkrysk.space / jasaio32sa.site / staging.gitlab.com），
123 个国家名大多是同一批中继的别名。所以 655 条里有大量等价节点，客户端会自动测速挑一个。
