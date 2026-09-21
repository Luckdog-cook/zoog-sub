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
TOP_N = 30; MOVE_MIN_KEEP = 5

def fingerprint():
    ts = int((time.time() - 8 * 3600) * 1000); r = random.randrange(2**31 - 1)
    plain = f"{EMAIL}|{PASSWORD}|{ts}|{r}|{sum([i * b for i, b in enumerate((EMAIL+PASSWORD+str(ts)+str(r)).encode(), 1)]) ^ 0}"
    pad = 16 - (len(plain.encode()) % 16)
    return base64.b64encode(_AES.new(AES_KEY.encode(), _AES.MODE_CBC, AES_IV.encode()).encrypt(plain.encode() + bytes([pad]) * pad)).decode()

def get_servers():
    r = requests.get(BASE_URL + "servers_v2", params={"email": EMAIL, "password": PASSWORD}, headers={"zoog-fp": fingerprint()}, timeout=12, verify=False)
    return r.json().get("servers", [])

def get_config(name):
    r = requests.get(BASE_URL + "server_config", params={"email": EMAIL, "password": PASSWORD, "config_name": name}, headers={"zoog-fp": fingerprint()}, timeout=12, verify=False)
    if r.status_code != 200: return None
    d = r.json()
    if "outbounds" not in d: return None
    try:
        ob = d["outbounds"][0]; vn = ob["settings"]["vnext"][0]; u = vn["users"][0]
        st = ob.get("streamSettings", {}); net, sec = st.get("network", "tcp"), st.get("security")
        res = {"address": vn["address"], "port": vn["port"], "id": u["id"], "encryption": u.get("encryption", "none"), "flow": u.get("flow", ""), "security": sec, "network": net, "fingerprint": None, "serverName": None, "allowInsecure": False, "path": "", "host": "", "mode": ""}
        if sec == "tls":
            t = st.get("tlsSettings", {}); res["serverName"] = t.get("serverName"); res["allowInsecure"] = t.get("allowInsecure", False)
        if net == "xhttp": x = st.get("xhttpSettings", {}); res["path"] = x.get("path", ""); res["mode"] = x.get("mode", "stream-one")
        return res
    except: return None

def _fetch_ip_list(url, region_key, seen):
    out = []
    try:
        r = requests.get(url, timeout=10)
        for line in r.text.splitlines():
            ip = line.strip().split(":")[0].split("#")[0].strip()
            if not ip or not ip.startswith("104."): continue
            if region_key == "mobile" and ip.startswith("172."): continue
            if ip not in seen: seen.add(ip); out.append(ip)
    except: pass
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
        with socket.create_connection((host, int(port)), timeout=timeout): return round((time.perf_counter() - t) * 1000, 1)
    except: return None

def to_uri(c, label, latency):
    p = [f"encryption={c['encryption']}", f"security={c['security']}", f"type={c['network']}"]
    if c.get("flow"): p.append(f"flow={c['flow']}")
    if c.get("serverName"): p.append(f"sni={c['serverName']}")
    if c.get("publicKey"): p.append(f"pbk={c['publicKey']}")
    if c.get("path"): p.append(f"path={c['path']}")
    name = f"{label}-{c.get('server_name','Zoog')}-{latency}ms"
    return f"vless://{c['id']}@{c['address']}:{c['port']}?{'&'.join(p)}#{name}"

def write_sub(links, path): Path(path).write_text(base64.b64encode("\n".join(links).encode()).decode(), encoding="utf-8")

def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    servers = get_servers(); all_nodes = []
    def process(srv):
        out = []
        for proto in srv.get("protocols", []):
            if proto.get("protocol") not in ("SS_XR_SYSPR", "SS_XR_PR"): continue
            cfg = get_config(proto.get("configName"))
            if cfg: cfg["server_name"] = srv.get("name"); out.append(cfg)
        return out
    with ThreadPoolExecutor(max_workers=8) as pool:
        for f in as_completed([pool.submit(process, s) for s in servers]): all_nodes.extend(f.result())
    
    per_region = {}
    for region_key, cfg in CF_SOURCES.items():
        cf_ips = fetch_cf_ips(region_key)
        candidates = [dict(node, address=ip) for node in all_nodes if node.get("security") == "tls" for ip in cf_ips]
        if not candidates: per_region[region_key] = []; continue
        def _probe(c): c["latency"] = tcp_probe(c["address"], c["port"]); return c
        results = []
        with ThreadPoolExecutor(max_workers=16) as pool:
            for f in as_completed([pool.submit(_probe, c) for c in candidates]):
                c = f.result()
                if c["latency"] is not None: results.append(c)
        results.sort(key=lambda x: x["latency"])
        per_region[region_key] = results

    for region_key, cfg in CF_SOURCES.items():
        full = per_region.get(region_key, [])
        write_sub([to_uri(c, cfg["label"], c["latency"]) for c in full], OUT_DIR / cfg["file"])
        write_sub([to_uri(c, cfg["label"], c["latency"]) for c in full[:TOP_N]], OUT_DIR / cfg["file"].replace(".txt", "-top30.txt"))
    
    all_full = [to_uri(c, cfg["label"], c["latency"]) for region_key, cfg in CF_SOURCES.items() for c in per_region.get(region_key, [])]
    write_sub(all_full, OUT_DIR / "zoog.txt")
    write_sub([to_uri(c, cfg["label"], c["latency"]) for region_key, cfg in CF_SOURCES.items() for c in per_region.get(region_key, [])[:TOP_N]], OUT_DIR / "zoog-top30.txt")

if __name__ == "__main__": main()
