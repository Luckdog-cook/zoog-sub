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

输出文件(output/ 下):
  zoog.txt        base64 订阅, 全部节点
  zoog-top30.txt  base64 订阅, 延迟最低的 30 个
  vless_links.txt 明文 vless:// 链接, 便于核对
"""

import base64
import os
import random
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

# Cloudflare 优选 IP 源(旧路径 BestCF/mobile.txt 等已 404,现用改版后的文件)
BESTCF_V4 = "https://raw.githubusercontent.com/ymyuuu/IPDB/main/BestCF/bestcfv4.txt"
CF_TOP_K = 5

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


def fetch_cf_ips():
    """拉取 Cloudflare 优选 IP(直连,不走代理)"""
    try:
        r = requests.get(BESTCF_V4, timeout=20)
        ips = []
        for line in r.text.splitlines():
            ip = line.strip().split(":")[0].split("#")[0].strip()
            if ip and (ip.startswith("104.") or ip.startswith("172.") or ip.startswith("162.")):
                if ip not in ips:
                    ips.append(ip)
        return ips
    except Exception as e:
        print(f"[警告] 优选 IP 拉取失败: {e}")
        return []


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

    # 直连版本(兜底,不套优选)
    direct_links = [to_uri(n, n.get("server_name", "Zoog")) for n in alive]

    # ---- 套用 Cloudflare 优选 IP(换地址、保留原 SNI) ----
    links = direct_links
    cf_ips = fetch_cf_ips()
    if cf_ips:
        print(f"[4/4] 优选 IP: 拿到 {len(cf_ips)} 个,开始测速...")
        ports = sorted({n["port"] for n in alive})
        lat_map = {}
        with ThreadPoolExecutor(max_workers=16) as ex:
            futs = {ex.submit(tcp_probe, ip, p): (ip, p) for ip in cf_ips for p in ports}
            for f in as_completed(futs):
                lat_map[futs[f]] = f.result()

        best_by_port = {}
        for p in ports:
            ranked = sorted([(l, ip) for (ip, pp), l in lat_map.items()
                             if pp == p and l is not None])
            best_by_port[p] = [ip for l, ip in ranked[:CF_TOP_K]]
            if ranked:
                print(f"      端口 {p}: 最快 {ranked[0][1]} ({ranked[0][0]}ms), 取前 {len(best_by_port[p])} 个")

        if any(best_by_port.values()):
            pooled = []
            for idx, n in enumerate(alive):
                pool_ips = best_by_port.get(n["port"])
                if not pool_ips:
                    continue
                ip = pool_ips[idx % len(pool_ips)]
                c = dict(n)
                if not c.get("serverName"):
                    c["serverName"] = c["address"]  # 保留原主机名做 SNI
                c["address"] = ip
                c["latency"] = lat_map.get((ip, n["port"]))
                pooled.append(c)
            if pooled:
                links = [to_uri(c, c.get("server_name", "Zoog")) for c in pooled]
                print(f"      优选套用完成: {len(links)} 条")
        else:
            print("[警告] 优选 IP 全部不可达,回退直连地址")
    else:
        print("[4/4] 未拿到优选 IP,使用节点直连地址")

    write_sub(links, OUT_DIR / "zoog.txt")
    write_sub(links[:TOP_N], OUT_DIR / "zoog-top30.txt")
    write_sub(direct_links, OUT_DIR / "zoog-direct.txt")
    (OUT_DIR / "vless_links.txt").write_text("\n".join(links), encoding="utf-8")

    print(f"完成! {OUT_DIR / 'zoog.txt'} ({len(links)} 条, 优选CF)")
    print(f"      {OUT_DIR / 'zoog-top30.txt'} ({min(TOP_N, len(links))} 条)")
    print(f"      {OUT_DIR / 'zoog-direct.txt'} ({len(direct_links)} 条, 直连兜底)")


if __name__ == "__main__":
    sys.exit(main())
