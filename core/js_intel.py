import requests
import re

def extract_js_files(target):
    try:
        r = requests.get(f"https://{target}", timeout=8)
        html = r.text
    except Exception:
        return []

    js_files = re.findall(r'src=["\'](.*?\.js)["\']', html)

    clean_js = []
    for js in js_files:
        if js.startswith("http"):
            clean_js.append(js)
        else:
            clean_js.append(f"https://{target}/{js.lstrip('/')}")

    return list(set(clean_js))
