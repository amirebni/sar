import requests
import base64
import json
import socket
import time
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==========================
# CONFIG
# ==========================

INPUT_FILE = "inputs.txt"
OUTPUT_FILE = "output.txt"
BLACKLIST_FILE = "blacklist.txt"

TIMEOUT_FETCH = 10
TIMEOUT_TCP = 3
MAX_PER_SOURCE = 50
MAX_WORKERS_FETCH = 10
MAX_WORKERS_CHECK = 30

RENAME = "Amir"

# ==========================
# LOGGING
# ==========================

logging.basicConfig(
    filename="run.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# ==========================
# UTILS
# ==========================

def is_ip(address):
    return re.match(r"^\d+\.\d+\.\d+\.\d+$", address) is not None

def try_decode(text):
    for _ in range(3):
        try:
            decoded = base64.b64decode(text).decode("utf-8")
            if decoded.strip():
                text = decoded
        except:
            break
    return text

def extract_configs(text):
    lines = text.split("\n")
    valid = []
    for l in lines:
        l = l.strip()
        if l.startswith(("vmess://","vless://","trojan://","ss://","ssr://","hy2://","tuic://")):
            valid.append(l)
    return valid

# ==========================
# FETCH
# ==========================

def fetch(url):
    try:
        r = requests.get(url, timeout=TIMEOUT_FETCH)
        if r.status_code == 200:
            return url, r.text.strip()
    except:
        pass
    return url, None

# ==========================
# PARSE HOST/PORT
# ==========================

def parse_host_port(line):
    try:
        if line.startswith("vmess://"):
            raw = line.split("://")[1].split("#")[0]
            data = json.loads(base64.b64decode(raw).decode("utf-8"))
            return data.get("add"), int(data.get("port"))

        if "://" in line:
            body = line.split("://")[1].split("#")[0]
            if "@" in body:
                body = body.split("@")[1]
            if ":" in body:
                host, port = body.split(":")[:2]
                port = port.split("?")[0]
                return host, int(port)

    except:
        pass

    return None, None

# ==========================
# TCP CHECK
# ==========================

def check_tcp(host, port):
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_TCP):
            latency = time.time() - start
            return True, latency
    except:
        return False, None

# ==========================
# SCORE
# ==========================

def score(line, latency):
    s = 0
    l = line.lower()

    if "tls" in l:
        s += 3
    if "grpc" in l:
        s += 2
    if "h2" in l:
        s += 1

    if latency < 0.5:
        s += 3
    elif latency < 1:
        s += 2
    elif latency < 2:
        s += 1
    else:
        s -= 2

    if "security=none" in l:
        s -= 3

    return s

# ==========================
# MAIN
# ==========================

def main():

    # Load blacklist
    try:
        with open(BLACKLIST_FILE) as f:
            blacklist = set(l.strip() for l in f if l.strip())
    except:
        blacklist = set()

    # Load sources
    with open(INPUT_FILE) as f:
        sources = [l.strip() for l in f if l.strip() and l.strip() not in blacklist]

    # -------- FETCH --------
    collected = []
    failed_sources = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_FETCH) as executor:
        futures = [executor.submit(fetch, url) for url in sources]
        for future in as_completed(futures):
            url, data = future.result()
            if not data:
                failed_sources.append(url)
                continue

            data = try_decode(data)
            configs = extract_configs(data)[:MAX_PER_SOURCE]
            collected.extend(configs)

    # Blacklist broken sources
    if failed_sources:
        with open(BLACKLIST_FILE, "a") as f:
            for fs in failed_sources:
                f.write(fs + "\n")

    # -------- DEDUP --------
    seen = set()
    unique = []

    for line in collected:
        key = line.split("#")[0]
        if key in seen:
            continue
        seen.add(key)
        unique.append(line)

    # -------- VALIDATE --------
    valid_servers = []

    def validate(line):
        host, port = parse_host_port(line)
        if not host or not port:
            return None

        if is_ip(host):
            return None

        ok, latency = check_tcp(host, port)
        if not ok:
            return None

        s = score(line, latency)
        return (line, latency, s)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_CHECK) as executor:
        futures = [executor.submit(validate, line) for line in unique]
        for future in as_completed(futures):
            result = future.result()
            if result:
                valid_servers.append(result)

    # -------- SORT --------
    valid_servers.sort(key=lambda x: (x[2], -x[1]), reverse=True)

    # -------- RENAME --------
    final = []
    for line, latency, s in valid_servers:
        base = line.split("#")[0]
        final.append(f"{base}#{RENAME}")

    # -------- OUTPUT --------
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(final))

    print(f"Total collected: {len(collected)}")
    print(f"Unique: {len(unique)}")
    print(f"Valid: {len(final)}")
    print("Done.")

if __name__ == "__main__":
    main()
