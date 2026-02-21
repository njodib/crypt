def kv_encode(d: dict) -> str:
    return "".join(f"{k}={v}&" for k, v in d.items())[:-1]

def kv_decode(cookie: str) -> dict:
    d = {}
    for attribute in cookie.split('&'):
        k,v = attribute.split('=')
        key = int(k) if k.isdigit() else k
        value = int(v) if v.isdigit() else v
        d[key] = value
    return d