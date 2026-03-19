#!/usr/bin/env python3
import re
from pathlib import Path
from bs4 import BeautifulSoup

def extract_form_logic(html_path):
    print(f"[*] Analyzing {html_path.name}...")
    try:
        with open(html_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        soup = BeautifulSoup(content, 'html.parser')
        form = soup.find('form')
        if not form:
            # Fallback to regex if BS4 fails on weird firmware HTML
            inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', content)
            return {"action": "unknown", "inputs": list(set(inputs))}
            
        action = form.get('action', 'cgi-bin/rex_cgi') # Fallback to RAX30 default
        inputs = {}
        for inp in form.find_all(['input', 'select', 'textarea']):
            name = inp.get('name')
            if name:
                type_ = inp.get('type', 'text')
                inputs[name] = "true" if type_ == "checkbox" else "fuzz_data"
                
        return {"action": action, "inputs": inputs}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    test_file = Path("/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/Netgear_RAX30/rootfs/webs/UPNP_upnp.html")
    result = extract_form_logic(test_file)
    print(f"[+] Extracted Logic: {result}")
