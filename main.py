import requests
import base64
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_FILE = "inputs.txt"
OUTPUT_FILE = "output.txt"

TIMEOUT_FETCH = 10
MAX_PER_SOURCE = 100
MAX_WORKERS_FETCH = 10

RENAME = "Amir"

logging.basicConfig(
    filename="run.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# -------------------------

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

def fetch(url):
    try:
        r = requests.get(url, timeout=TIMEOUT_FETCH)
        if r.status_code == 200:
            return url, r.text.strip()
    except:
        pass
    return url, None

def score(line):
    s = 0
    l = line.lower()

    if "tls" in l:
        s += 3
    if "grpc" in l:
        s += 2
    if "h2" in l:
        s += 1
    if "reality" in l:
        s += 3
    if "security=none" in l:
        s -= 2

    return s

# -------------------------

def main():

    with open(INPUT_FILE) as f:
        sources = [l.strip() for l in f if l.strip()]

    collected = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_FETCH) as executor:
        futures = [executor.submit(fetch, url) for url in sources]
        for future in as_completed(futures):
            url, data = future.result()
            if not data:
                logging.info(f"Failed source: {url}")
                continue

            data = try_decode(data)
            configs = extract_configs(data)[:MAX_PER_SOURCE]
            collected.extend(configs)

    # Dedup
    seen = set()
    unique = []

    for line in collected:
        key = line.split("#")[0]
        if key in seen:
            continue
        seen.add(key)
        unique.append(line)

    # Sort
    unique.sort(key=lambda x: score(x), reverse=True)

    # Rename
    final = []
    for line in unique:
        base = line.split("#")[0]
        final.append(f"{base}#{RENAME}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(final))

    print("Total collected:", len(collected))
    print("Unique:", len(unique))
    print("Final:", len(final))
    print("Done.")

if __name__ == "__main__":
    main()
