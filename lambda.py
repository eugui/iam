#!/usr/bin/env python3

import base64, os, subprocess, urllib.request
from pathlib import Path
import pickle  # insecure deserialization

def _pickle_case(event):
    b64 = event.get("pickle_b64","")
    data = pickle.loads(base64.b64decode(b64))  # intentionally unsafe
    return {"ok": True, "type": str(type(data))}

def _cmd_case(event):
    name = event.get("name","world")
    rc = os.system(f"echo Hello {name}")  # intentionally unsafe
    return {"rc": rc}

def _eval_case(event):
    expr = event.get("expr","1+2")
    return {"result": eval(expr)}  # intentionally unsafe

def _traversal_case(event):
    name = event.get("name","a.txt")
    p = Path("/tmp")/name  # intentionally unsafe
    try:
        return {"path": str(p), "exists": p.exists(), "content": p.read_text()[:200]}
    except Exception as e:
        return {"error": str(e), "path": str(p)}

def _ssrf_case(event):
    url = event.get("url","http://httpbin.org/get")
    with urllib.request.urlopen(url, timeout=3) as r:
        return {"status": r.status, "len": len(r.read())}

def lambda_handler(event, context):
    e = event or {}
    if "pickle_b64" in e: return _pickle_case(e)
    if "name" in e and "traversal" not in e: return _cmd_case(e)
    if "expr" in e: return _eval_case(e)
    if "traversal" in e: return _traversal_case(e)
    if "url" in e: return _ssrf_case(e)
    return {"ok": True, "hint": "send one of: {pickle_b64|name|expr|traversal|url}"}
