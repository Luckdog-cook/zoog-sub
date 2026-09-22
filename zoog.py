#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zoog.py — 抓取 ZoogVPN 节点并生成订阅文件

修复记录(2026-09-22):
  1. zoog-fp 校验和算法修正: 旧版用 sum(byte*idx)^0, 正确算法是 acc ^= byte*idx。
     指纹错误导致 server_config 一律 403/404, 这是"永远抓不到节点"的根因。
  2. 时间戳改用 App 原始算法: UTC 时间串 -> mktime 解析(东八区)。
  3. 移除对 BestCF 优选 IP 的依赖: ymyuuu/IPDB 的 BestCF/*.txt 已 404 下线,
     旧脚本拿到 0 个 IP -> 候选为空 -> 写出 base64("") 空文件, 这是第二层根因。
     现在直接用节点真实地址生成订阅。
  4. 输出目录支持 ZOOG_OUTPUT 环境变量(默认 ./output)。

输出文件(output/ 下, 每个运营商一套, 前缀 zoog/t-zoog/u-zoog/m-zoog):
  {p}.txt        base64 订阅, 精简 + 全量(节点名带 [精简]/[全量] 标签)
  {p}-lite.txt   只精简: 每个真实出口 x 5 个优选 IP
  {p}-full.txt   只全量: 每个节点 x 5 个优选 IP
  {p}-top30.txt  前 30 条(精简优先)
  zoog-direct.txt 不套 CF 优选的直连兜底
  vless_links.txt 明文 vless:// 链接, 便于核对
"""

import base64
import os
import random
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote

import requests
import urllib3
from Crypto.Cipher import AES as _AES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

EMAIL = os.environ.get("ZOOG_EMAIL", "2fa478f4@zoogvpn.ndr")
PASSWORD = os.environ.get("ZOOG_PASSWORD", "6EB6298BFE14724D869A07A5F94642D8")
BASE_URL = os.environ.get("ZOOG_BASE", "https://78.46.85.211/RESTF-1.0.3/rest/api/")
OUT_DIR = Path(os.environ.get("ZOOG_OUTPUT", "./output"))

AES_KEY = "cJfUueyJiTDK1cEqETnxPuHs3YUrehAd"
AES_IV = "CufmfUjCLT8MiY0z"

PROTOCOLS = ("SS_XR_SYSPR", "SS_XR_PR")
TOP_N = 30

# Cloudflare 优选 IP 源
#  主源 vipmc838/cf_best_ip: 带运营商维度(默认/电信/联通/移动),按实测带宽排序
#  备源 ymyuuu/IPDB BestCF:   无运营商维度,仅作兜底
#  注: 旧脚本用的 BestCF/mobile.txt 等路径已 404,git 历史中也不存在该文件
CF_JSON = "https://raw.githubusercontent.com/vipmc838/cf_best_ip/main/cloudflare_bestip.json"
BESTCF_V4 = "https://raw.githubusercontent.com/ymyuuu/IPDB/main/BestCF/bestcfv4.txt"
CF_TOP_K = 5

# 运营商 -> 输出文件名前缀
ISP_FILES = {"默认": "zoog", "电信": "t-zoog", "联通": "u-zoog", "移动": "m-zoog"}

# 订阅内分类标签(写进节点名,客户端可按关键字过滤)
TAG_LITE = "[精简]"      # 按真实出口去重 x 每个优选 IP
TAG_RR = "[轮流]"        # 每个节点轮流分配 1 个优选 IP
TAG_CROSS = "[全交叉]"   # 每个节点 x 每个优选 IP(全组合)
TAG_DIRECT = "[直连]"    # 不套 CF 优选

# 真实出口主机前缀 -> 国家(精简列表用,取代 123 个虚名)
EXIT_CN = {
    "nl": "荷兰", "sg": "新加坡", "us": "美国", "fr": "法国", "es": "西班牙",
    "de": "德国", "jp": "日本", "gb": "英国", "uk": "英国", "ca": "加拿大",
    "au": "澳洲", "kr": "韩国", "in": "印度", "br": "巴西", "tr": "土耳其",
    "se": "瑞典", "ch": "瑞士", "it": "意大利", "ru": "俄罗斯", "pl": "波兰",
    "hk": "香港", "tw": "台湾", "vn": "越南", "th": "泰国", "id": "印尼",
}

_sess = requests.Session()
_sess.verify = False


# ---------- 指纹(App SecretUtils 复刻) ----------
def checksum(payload: str) -> int:
    """SecretUtils.b():acc ^= byte * 位置(1 起)"""
    acc = 0
    for idx, byte in enumerate(payload.encode("utf-8"), start=1):
        acc ^= byte * idx
    return acc


def current_timestamp_ms() -> int:
    """Q.i():UTC 时间串按本地时区解析(东八区)"""
    utc_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    return int(time.mktime(time.strptime(utc_str, "%Y-%m-%d %H:%M:%S")) * 1000)


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len


def fingerprint() -> str:
    ts = current_timestamp_ms()
    r = random.randrange(2**31 - 1)
    payload = f"{EMAIL}|{PASSWORD}|{ts}|{r}|{checksum(EMAIL + PASSWORD + str(ts) + str(r))}"
    cipher = _AES.new(AES_KEY.encode(), _AES.MODE_CBC, AES_IV.encode())
    return base64.b64encode(cipher.encrypt(_pkcs7_pad(payload.encode()))).decode()


def make_headers(region=None):
    h = {
        "zoog-fp": fingerprint(),
        "Accept-Language": "zh",
        "User-Agent": "android 4.3.1",
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive",
    }
    if region:
        h["region"] = region
    return h


# ---------- 抓取 ----------
def get_servers():
    r = _sess.get(BASE_URL + "servers_v2",
                  params={"email": EMAIL, "password": PASSWORD},
                  headers=make_headers("Auto"), timeout=20)
    r.raise_for_status()
    data = r.json()
    if data.get("error"):
        raise Exception(f"API error: {data.get('error')}")
    servers = data.get("servers", [])
    print(f"[1/4] 服务器列表: {len(servers)} 台")
    return servers


def get_config(config_name):
    for attempt in range(3):
        try:
            r = _sess.get(BASE_URL + "server_config",
                          params={"email": EMAIL, "password": PASSWORD, "config_name": config_name},
                          headers=make_headers(), timeout=20)
            if r.status_code == 200:
                d = r.json()
                if "outbounds" in d:
                    return parse_xray(d)
                return None
            if r.status_code in (429, 500, 502, 503, 504):
                time.sleep(1 + attempt)
                continue
            return None
        except Exception:
            time.sleep(0.5 + attempt)
    return None


def parse_xray(d):
    """解析 Xray/VLESS 配置,兼容 tls / reality / ws / xhttp"""
    try:
        ob = d["outbounds"][0]
        if ob.get("protocol") != "vless":
            return None
        vn = ob["settings"]["vnext"][0]
        u = vn["users"][0]
        st = ob.get("streamSettings", {})
        net = st.get("network", "tcp")
        sec = st.get("security")

        res = {
            "address": vn["address"], "port": vn["port"], "id": u["id"],
            "encryption": u.get("encryption", "none"), "flow": u.get("flow", ""),
            "security": sec, "network": net,
            "fingerprint": None, "serverName": None, "publicKey": None,
            "shortId": None, "path": "", "host": "", "mode": "",
            "allowInsecure": False,
        }

        if sec == "tls":
            t = st.get("tlsSettings", {})
            res["serverName"] = t.get("serverName")
            res["allowInsecure"] = t.get("allowInsecure", False)
            res["fingerprint"] = t.get("fingerprint")
        elif sec == "reality":
            rr = st.get("realitySettings", {})
            res["serverName"] = rr.get("serverName")
            res["publicKey"] = rr.get("publicKey")
            res["shortId"] = rr.get("shortId")
            res["fingerprint"] = rr.get("fingerprint", "chrome")

        if net == "ws":
            w = st.get("wsSettings", {})
            res["path"] = w.get("path", "")
            res["host"] = w.get("headers", {}).get("Host", "")
        elif net == "xhttp":
            x = st.get("xhttpSettings", {})
            res["path"] = x.get("path", "")
            res["mode"] = x.get("mode", "stream-one")
        return res
    except Exception:
        return None


def to_uri(c, label):
    p = [f"encryption={c['encryption']}"]
    if c.get("flow"):
        p.append(f"flow={c['flow']}")
    if c.get("security"):
        p.append(f"security={c['security']}")
    if c.get("serverName"):
        p.append(f"sni={c['serverName']}")
    if c.get("publicKey"):
        p.append(f"pbk={c['publicKey']}")
    if c.get("shortId"):
        p.append(f"sid={c['shortId']}")
    if c.get("fingerprint"):
        p.append(f"fp={c['fingerprint']}")
    p.append(f"type={c['network']}")
    if c.get("path"):
        p.append(f"path={c['path']}")
    if c.get("mode"):
        p.append(f"mode={c['mode']}")
    if c.get("host"):
        p.append(f"host={c['host']}")
    if c.get("allowInsecure"):
        p.append("allowInsecure=1")

    lat = c.get("latency")
    tail = f"-{int(lat)}ms" if lat is not None else ""
    name = quote(f"{label}{tail}", safe="")
    return f"vless://{c['id']}@{c['address']}:{c['port']}?{'&'.join(p)}#{name}"


def exit_label(host: str) -> str:
    """把真实出口主机名翻译成 国家-主机, 用于精简列表命名。"""
    h = (host or "").lower()
    m = re.match(r"^([a-z]{2})\d*[-.]", h)
    cn = EXIT_CN.get(m.group(1)) if m else None
    # 出口主机大多在 Cloudflare 后面, IP 归属查不到真实落地, 只能靠 Zoog 自己的命名前缀
    return f"{cn}-{host}" if cn else f"其他-{host}"


def tcp_probe(host, port, timeout=3.0):
    t = time.perf_counter()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return round((time.perf_counter() - t) * 1000, 1)
    except Exception:
        return None


def write_sub(links, path):
    Path(path).write_text(
        base64.b64encode("\n".join(links).encode()).decode(), encoding="utf-8")


def _valid_v4(ip: str) -> bool:
    return bool(ip) and ":" not in ip and ip[0].isdigit()


def fetch_isp_ips():
    """按运营商拉取 Cloudflare 优选 IP,返回 {运营商: [ip, ...]}"""
    try:
        r = requests.get(CF_JSON, timeout=20)
        best = r.json().get("最优IP", {})
        out = {}
        for isp in ISP_FILES:
            ips = [x.strip() for x in best.get(isp, []) if _valid_v4(x.strip())]
            if ips:
                out[isp] = ips
        if out:
            print(f"      主源: {', '.join(f'{k}{len(v)}' for k, v in out.items())}")
            return out
    except Exception as e:
        print(f"[警告] 优选 IP 主源失败: {e}")

    # 兜底:无运营商维度的单一列表
    try:
        r = requests.get(BESTCF_V4, timeout=20)
        ips = []
        for line in r.text.splitlines():
            ip = line.strip().split(":")[0].split("#")[0].strip()
            if _valid_v4(ip) and ip not in ips:
                ips.append(ip)
        if ips:
            print(f"      备源: {len(ips)} 个(无运营商区分)")
            return {"默认": ips}
    except Exception as e:
        print(f"[警告] 优选 IP 备源失败: {e}")
    return {}


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[诊断] 输出目录: {OUT_DIR}")
    print(f"[诊断] 账号: {EMAIL}")

    servers = get_servers()

    jobs = []
    for srv in servers:
        for proto in srv.get("protocols", []):
            if proto.get("protocol") not in PROTOCOLS:
                continue
            cn = proto.get("configName")
            if cn:
                jobs.append((srv.get("name"), proto.get("protocol"), cn))

    print(f"[2/4] 待抓配置: {len(jobs)} 个")

    nodes = []

    def worker(job):
        name, pname, cn = job
        cfg = get_config(cn)
        if cfg:
            cfg["server_name"] = name
            cfg["protocol"] = pname
            return cfg
        return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        futs = [pool.submit(worker, j) for j in jobs]
        done = 0
        for f in as_completed(futs):
            done += 1
            c = f.result()
            if c:
                nodes.append(c)
            if done % 50 == 0 or done == len(jobs):
                print(f"  进度 {done}/{len(jobs)} 成功 {len(nodes)}")
            time.sleep(0.05)

    print(f"[3/4] 成功解析节点: {len(nodes)}")
    if not nodes:
        raise SystemExit("抓取失败: 没有拿到任何节点配置,终止(避免提交空订阅)")

    # 去重(同一出口会被多个国家复用)
    uniq = {}
    for n in nodes:
        key = (n["id"], n["address"], n["port"], n["network"], n.get("path", ""))
        if key not in uniq:
            uniq[key] = n
    nodes = list(uniq.values())
    print(f"      去重后: {len(nodes)} 个")

    # 延迟探测(只对唯一 address:port,避免重复打)
    targets = {}
    with ThreadPoolExecutor(max_workers=16) as pool:
        futs = {}
        for n in nodes:
            key = (n["address"], n["port"])
            if key not in targets:
                targets[key] = None
                futs[pool.submit(tcp_probe, key[0], key[1])] = key
        for f in as_completed(futs):
            targets[futs[f]] = f.result()

    alive = []
    for n in nodes:
        lat = targets.get((n["address"], n["port"]))
        if lat is None:
            continue
        n["latency"] = lat
        alive.append(n)

    if not alive:
        print("[警告] 全部节点 TCP 不可达,改为不标注延迟直接输出")
        alive = nodes
        for n in alive:
            n["latency"] = None

    alive.sort(key=lambda x: (x["latency"] is None, x["latency"] or 0))
    print(f"      存活: {len(alive)} 个")

    # 精简集合: 每个真实出口(主机+端口+传输)只保留延迟最低的那一个
    # 131 个节点其实只落在少数几个出口上, 国家名基本是同一批中继的别名
    lite_map = {}
    for n in alive:  # alive 已按延迟升序
        k = (n["address"], n["port"], n["network"])
        if k not in lite_map:
            lite_map[k] = n
    lite_nodes = list(lite_map.values())
    print(f"      精简(按真实出口去重): {len(lite_nodes)} 个")

    # 直连版本(兜底,不套优选)
    direct_links = [to_uri(n, f"{TAG_DIRECT} {n.get('server_name', 'Zoog')}")
                    for n in alive]
    write_sub(direct_links, OUT_DIR / "zoog-direct.txt")
    print(f"      直连兜底: {len(direct_links)} 条")

    isp_ips = fetch_isp_ips()
    if not isp_ips:
        print("[4/4] 未拿到任何优选 IP,全部回退直连地址")
        for prefix in ISP_FILES.values():
            write_sub(direct_links, OUT_DIR / f"{prefix}.txt")
            write_sub(direct_links[:TOP_N], OUT_DIR / f"{prefix}-top30.txt")
            write_sub(direct_links, OUT_DIR / f"{prefix}-lite.txt")
            write_sub(direct_links, OUT_DIR / f"{prefix}-rr.txt")
            write_sub(direct_links, OUT_DIR / f"{prefix}-full.txt")
        (OUT_DIR / "vless_links.txt").write_text("\n".join(direct_links), encoding="utf-8")
        print("完成!")
        return

    print("[4/4] 按运营商套用优选 IP(换地址 + 保留原 SNI)...")
    ports = sorted({n["port"] for n in alive})
    default_links = direct_links

    for isp, prefix in ISP_FILES.items():
        ips = isp_ips.get(isp) or isp_ips.get("默认") or []
        if not ips:
            print(f"      [{isp}] 无可用 IP,跳过")
            continue

        # 只测该运营商的候选 IP
        lat_map = {}
        with ThreadPoolExecutor(max_workers=16) as ex:
            futs = {ex.submit(tcp_probe, ip, p): (ip, p) for ip in ips for p in ports}
            for f in as_completed(futs):
                lat_map[futs[f]] = f.result()

        best_by_port = {}
        for p in ports:
            ranked = sorted([(l, ip) for (ip, pp), l in lat_map.items()
                             if pp == p and l is not None])
            best_by_port[p] = [ip for l, ip in ranked[:CF_TOP_K]]

        def lite_name(c):
            h = c.get("orig_host") or ""
            lb = exit_label(h)
            if lb == h:  # SNI 是伪装域名(如 staging.gitlab.com), 回退真实地址
                lb = exit_label(c.get("orig_addr", ""))
            return lb

        if not any(best_by_port.values()):
            print(f"      [{isp}] 优选 IP 全部不可达,回退直连")
            lite_links = [to_uri(n, f"{TAG_LITE} {exit_label(n.get('serverName') or n['address'])}")
                          for n in lite_nodes]
            rr_links = cross_links = full_links = direct_links
            fast = None
        else:
            # 换 address 为优选 IP, 保留原主机名做 SNI
            #   mode="all" 全组合交叉: 每个节点 x 每个优选 IP
            #   mode="rr"  轮流交换:   每个节点轮流拿 1 个优选 IP
            def cross(nodes, mode="all"):
                out = []
                for idx, n in enumerate(nodes):
                    pool_ips = best_by_port.get(n["port"])
                    if not pool_ips:
                        continue
                    ips = pool_ips if mode == "all" else [pool_ips[idx % len(pool_ips)]]
                    for ip in ips:
                        c = dict(n)
                        if not c.get("serverName"):
                            c["serverName"] = c["address"]
                        host = c["serverName"]
                        c["address"] = ip
                        c["latency"] = lat_map.get((ip, n["port"]))
                        c["cf_ip"] = ip
                        c["orig_host"] = host
                        c["orig_addr"] = n["address"]
                        out.append(c)
                return out

            def build(cf, tag, name_of):
                return [to_uri(c, f"{tag} {name_of(c)}-{c['cf_ip']}") for c in cf]

            lite_cf = cross(lite_nodes, "all")
            rr_cf = cross(alive, "rr")
            full_cf = cross(alive, "all")

            lite_links = build(lite_cf, TAG_LITE, lite_name)
            rr_links = build(rr_cf, TAG_RR,
                             lambda c: c.get("server_name", "Zoog"))
            full_links = build(full_cf, TAG_CROSS,
                               lambda c: c.get("server_name", "Zoog"))
            fast = min([v for v in lat_map.values() if v is not None], default=None)

        # 主订阅 = 精简 + 轮流 + 全交叉(都带标签,客户端可按标签过滤/分组)
        merged = lite_links + rr_links + full_links

        write_sub(merged, OUT_DIR / f"{prefix}.txt")
        write_sub(lite_links, OUT_DIR / f"{prefix}-lite.txt")
        write_sub(rr_links, OUT_DIR / f"{prefix}-rr.txt")
        write_sub(full_links, OUT_DIR / f"{prefix}-full.txt")

        # top30: 精简优先, 再轮流, 再全交叉
        write_sub(merged[:TOP_N], OUT_DIR / f"{prefix}-top30.txt")

        if isp == "默认":
            default_links = merged
        print(f"      [{isp:4}] 精简 {len(lite_links)} + 轮流 {len(rr_links)} "
              f"+ 全交叉 {len(full_links)} = {len(merged)} 条 -> {prefix}.txt "
              f"(+lite/rr/full/top30)  最快 {fast}ms")

    (OUT_DIR / "vless_links.txt").write_text("\n".join(default_links), encoding="utf-8")
    print("完成!")


if __name__ == "__main__":
    sys.exit(main())
