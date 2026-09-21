import base64, os, random, socket, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import requests, urllib3
from Crypto.Cipher import AES as _AES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

EMAIL    = os.environ.get("ZOOG_EMAIL", "2fa478f4@zoogvpn.ndr")
PASSWORD = os.environ.get("ZOOG_PASSWORD", "6EB6298BFE14724D869A07A5F94642D8")
BASE_URL = os.environ.get("ZOOG_BASE", "https://78.46.85.211/RESTF-1.0.3/rest/api/")
OUT_DIR  = Path("./output")

AES_KEY = "cJfUueyJiTDK1cEqETnxPuHs3YUrehAd"
AES_IV  = "CufmfUjCLT8MiY0z"

CF_SOURCES = {
    "mobile": {"file": "m-zoog.txt", "label": "zoog-移动",
               "primary": "https://raw.githubusercontent.com/ymyuuu/IPDB/main/BestCF/mobile.txt",
               "fallback": "https://raw.githubusercontent.com/ymyuuu/IPDB/main/BestCF/all.txt"},
    "unicom": {"file": "u-zoog.txt", "label": "zoog-联通",
               "primary": "https://raw.githubusercontent.com/ymyuuu/IPDB/main/BestCF/unicom.txt"},
    "telecom": {"file": "t-zoog.txt", "label": "zoog-电信",
                "primary": "https://raw.githubusercontent.com/ymyuuu/IPDB/main/BestCF/telecom.txt"},
}
TOP_N = 30
MOVE_MIN_KEEP = 5

# 全局 session 复用连接
_sess = requests.Session()
_sess.verify = False


def fingerprint():
    ts = int((time.time() - 8 * 3600) * 1000)
    r = random.randrange(2**31 - 1)
    plain = f"{EMAIL}|{PASSWORD}|{ts}|{r}|{sum([i * b for i, b in enumerate((EMAIL+PASSWORD+str(ts)+str(r)).encode(), 1)]) ^ 0}"
    pad = 16 - (len(plain.encode()) % 16)
    return base64.b64encode(_AES.new(AES_KEY.encode(), _AES.MODE_CBC, AES_IV.encode()).encrypt(plain.encode() + bytes([pad]) * pad)).decode()


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


def get_servers():
    r = _sess.get(BASE_URL + "servers_v2",
                  params={"email": EMAIL, "password": PASSWORD},
                  headers=make_headers("Auto"), timeout=12)
    r.raise_for_status()
    data = r.json()
    if data.get("error"):
        raise Exception(f"API 报错: {data['error']}")
    servers = data.get("servers", [])
    print(f"[诊断] API 返回服务器数量: {len(servers)}")
    if not servers:
        raise Exception("获取失败!ZoogVPN 没有返回任何节点,账号可能已失效或过期。")
    return servers


def get_config(name):
    """抓单个节点配置，带上完整请求头 + 重试 + 节流"""
    url = BASE_URL + "server_config"
    params = {"email": EMAIL, "password": PASSWORD, "config_name": name}

    for attempt in range(3):
        try:
            r = _sess.get(url, params=params, headers=make_headers(), timeout=12)
            if r.status_code == 200:
                d = r.json()
                if "outbounds" in d:
                    return parse_xray(d)
                # 有时会返回空对象或者非 Xray 配置
                return None
            if r.status_code in (429, 500, 502, 503, 504):
                time.sleep(1 + attempt)
                continue
            return None
        except Exception:
            time.sleep(0.5 + attempt)
            continue
    return None


def parse_xray(d):
    try:
        ob = d["outbounds"][0]
        if ob.get("protocol") != "vless":
            return None
        vn = ob["settings"]["vnext"][0]
        u = vn["users"][0]
        st = ob.get("streamSettings", {})
        net, sec = st.get("network", "tcp"), st.get("security")
        res = {"address": vn["address"], "port": vn["port"], "id": u["id"],
               "encryption": u.get("encryption", "none"), "flow": u.get("flow", ""),
               "security": sec, "network": net, "fingerprint": None, "serverName": None,
               "allowInsecure": False, "path": "", "host": "", "mode": ""}
        if sec == "tls":
            t = st.get("tlsSettings", {})
            res["serverName"] = t.get("serverName")
            res["allowInsecure"] = t.get("allowInsecure", False)
        elif sec == "reality":
            r = st.get("realitySettings", {})
            res["serverName"] = r.get("serverName")
            res["publicKey"] = r.get("publicKey")
            res["shortId"] = r.get("shortId")
            res["fingerprint"] = r.get("fingerprint", "chrome")
        if net == "xhttp":
            x = st.get("xhttpSettings", {})
            res["path"] = x.get("path", "")
            res["mode"] = x.get("mode", "stream-one")
        elif net == "ws":
            w = st.get("wsSettings", {})
            res["path"] = w.get("path", "")
            res["host"] = w.get("headers", {}).get("Host", "")
        return res
    except Exception:
        return None


def _fetch_ip_list(url, region_key, seen):
    out = []
    try:
        r = requests.get(url, timeout=10)
        for line in r.text.splitlines():
            ip = line.strip().split(":")[0].split("#")[0].strip()
            if not ip or not ip.startswith("104."):
                continue
            if region_key == "mobile" and ip.startswith("172."):
                continue
            if ip not in seen:
                seen.add(ip); out.append(ip)
    except Exception:
        pass
    return out


def fetch_cf_ips(region_key):
    cfg = CF_SOURCES[region_key]; seen = set()
    pool = _fetch_ip_list(cfg["primary"], region_key, seen)
    if region_key == "mobile" and len(pool) < MOVE_MIN_KEEP and cfg.get("fallback"):
        pool += _fetch_ip_list(cfg["fallback"], region_key, seen)
    return pool


def tcp_probe(host, port, timeout=3.0):
    t = time.perf_counter()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return round((time.perf_counter() - t) * 1000, 1)
    except Exception:
        return None


def to_uri(c, label, latency):
    p = [f"encryption={c['encryption']}", f"security={c['security']}", f"type={c['network']}"]
    if c.get("flow"): p.append(f"flow={c['flow']}")
    if c.get("serverName"): p.append(f"sni={c['serverName']}")
    if c.get("publicKey"): p.append(f"pbk={c['publicKey']}")
    if c.get("shortId"): p.append(f"sid={c['shortId']}")
    if c.get("fingerprint"): p.append(f"fp={c['fingerprint']}")
    if c.get("path"): p.append(f"path={c['path']}")
    if c.get("mode"): p.append(f"mode={c['mode']}")
    if c.get("host"): p.append(f"host={c['host']}")
    if c.get("allowInsecure"): p.append("allowInsecure=1")
    name = f"{label}-{c.get('server_name','Zoog')}-{latency}ms"
    return f"vless://{c['id']}@{c['address']}:{c['port']}?{'&'.join(p)}#{name}"


def write_sub(links, path):
    Path(path).write_text(base64.b64encode("\n".join(links).encode()).decode(), encoding="utf-8")


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print("[1/3] 抓取 ZoogVPN 全部节点...")
    servers = get_servers()

    # 收集所有需要抓的 config_name
    jobs = []
    for srv in servers:
        for proto in srv.get("protocols", []):
            if proto.get("protocol") not in ("SS_XR_SYSPR", "SS_XR_PR"):
                continue
            cn = proto.get("configName")
            if cn:
                jobs.append((srv.get("name"), cn))

    print(f"[诊断] 待抓配置数: {len(jobs)}")

    all_nodes = []
    def worker(job):
        name, cn = job
        cfg = get_config(cn)
        if cfg:
            cfg["server_name"] = name
            return cfg
        return None

    # 并发降到 2，避免被 API 限流
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(worker, j) for j in jobs]
        done = 0
        for f in as_completed(futures):
            done += 1
            try:
                c = f.result()
                if c:
                    all_nodes.append(c)
            except Exception:
                pass
            if done % 20 == 0 or done == len(jobs):
                print(f"  进度 {done}/{len(jobs)} 成功 {len(all_nodes)}")
            time.sleep(0.05)  # 节流

    print(f"[诊断] 成功解析节点: {len(all_nodes)}")
    if not all_nodes:
        raise Exception("获取失败!所有服务器配置都拿不到,接口可能被屏蔽,或账号已失效。")

    print("[2/3] 三网拉 IP + 生成候选 + 测速...")
    per_region = {}
    for region_key, cfg in CF_SOURCES.items():
        cf_ips = fetch_cf_ips(region_key)
        print(f"  [{region_key}] 拿到 {len(cf_ips)} 个优选 IP")
        if not cf_ips:
            per_region[region_key] = []
            continue

        candidates = []
        for node in all_nodes:
            if node.get("security") != "tls":
                continue
            for ip in cf_ips:
                v = node.copy()
                v["address"] = ip
                candidates.append(v)

        if not candidates:
            per_region[region_key] = []
            continue

        def _probe(c):
            c["latency"] = tcp_probe(c["address"], c["port"])
            return c

        results = []
        with ThreadPoolExecutor(max_workers=16) as pool:
            for f in as_completed([pool.submit(_probe, c) for c in candidates]):
                c = f.result()
                if c["latency"] is not None:
                    results.append(c)
        results.sort(key=lambda x: x["latency"])
        per_region[region_key] = results
        print(f"  [{region_key}] 存活 {len(results)}")

    print("[3/3] 生成订阅文件...")
    for region_key, cfg in CF_SOURCES.items():
        full = per_region.get(region_key, [])
        write_sub([to_uri(c, cfg["label"], c["latency"]) for c in full],
                  OUT_DIR / cfg["file"])
        write_sub([to_uri(c, cfg["label"], c["latency"]) for c in full[:TOP_N]],
                  OUT_DIR / cfg["file"].replace(".txt", "-top30.txt"))

    all_full = [to_uri(c, cfg["label"], c["latency"])
                for region_key, cfg in CF_SOURCES.items()
                for c in per_region.get(region_key, [])]
    all_top = [to_uri(c, cfg["label"], c["latency"])
               for region_key, cfg in CF_SOURCES.items()
               for c in per_region.get(region_key, [])[:TOP_N]]
    write_sub(all_full, OUT_DIR / "zoog.txt")
    write_sub(all_top, OUT_DIR / "zoog-top30.txt")

    print(f"\n完成!总节点 {len(all_full)} 个")


if __name__ == "__main__":
    main()
