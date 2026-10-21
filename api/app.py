from flask import Flask, request, jsonify, render_template_string
import hmac
import hashlib
import requests
import string
import random
import secrets
import json
import base64
import re
import os
import time
import threading
import uuid
import concurrent.futures
from datetime import datetime, timezone
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
app.config["PROPAGATE_EXCEPTIONS"] = False

# ═══════════════════════════════════════════════════════════════════════════
#  KONFIGURASI API FF
# ═══════════════════════════════════════════════════════════════════════════
APP_ID = 100067
RELEASE_VER = "OB55"
HEX_KEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
URL_GUEST_REGISTER = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
URL_TOKEN_GRANT = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
URL_MAJOR_LOGIN = "https://loginbp.ppmainecoonghj.com/MajorLogin"
URL_MAJOR_REGISTER = "https://loginbp.ppmainecoonghj.com/MajorRegister"
URL_NEWBIE_CHOICE = "https://loginbp.ppmainecoonghj.com/ChooseNewbieChoice"
FORCE_REGION = "ID"
MAX_COUNT = 15

_AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
_AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
FIELD_22 = bytes.fromhex("4747524501010100620200001052aa0d669c6a368f08338060d2ee0690053af84a41edcd3558556ec10f24f46c93ac64ca41a16732c46a2cb071246a79b8929032f9e1b6f4ef331bd53cabf29b09b97349a46e9863c0314e1a0d80819fef8aabf03876b3d037db354a7ccb5c1bce96411fb3753f6f50e44c69c4ed617fa30efb8ffc0517ff2f636739be1f304d999cfd6fd48bf69454199794c3dc88f55a4bdbd66534d5a061359cdfd1fb680cd37918df9fdb3cf7d80067b0a3506c90063cf62b2ccec11e23913a2fd7c4ef091331967bb518a5ad1e551146b90821be800883abadde39d6c80a5d798611466c748f075481806c5842ce45e6bd4e3368ec08fe2ec41ceb880cd86249eb71693f79f0bccf9e590c3fae12519fe08c7a1905d0927690109e0df28574bb14847225db1a59230e6662ed7730e15ff9a6c815cb41b420edeada735a4b03e181037c37c2c850257311df2f07b0a56e759372cbd0268e3f13a292ee4373e38ab5096e0342a5e0d7fec6da2bbc265d74baadd2b24ee4f74862f82c21d6694bac53f8ce80312a30068a6276a641c19b11d0305c6fe2f531ac7de578b29f543697f5c73663e6f23aa15277b6122dcd4d4171e38f9ac0b173f39c58416a16c5c1f4a35acd065ce78f449cf538a249339e763272d458e4ed86c976591a9c066b3a37111e44091eb6b5a795249f3e5145db022a6055f2cc675936391312f688f89627845df222a91156555225be36f9714a0ba50246d0f003bda3c9c1292ab73b4f79635ddd023218eda93a302d79e023404c14396544a930b98ed54771aca7fec10d095587685b473e81a9619764fad9256529dcd6e911f4f4629612287d4ee3ec5389f6ec4ec020b0e2aac017232a9197be9e46239ce690fe5d4872b2e98e651510c971667f3aca8b59f3e9d50e43")

IP_POOL = [f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(1000)]
def get_ip_headers():
    ip = random.choice(IP_POOL)
    return {"X-Forwarded-For": ip, "X-Real-IP": ip, "CF-Connecting-IP": ip}

UA_POOL = [
    "GarenaMSDK/4.0.39(SM-A325M;Android 13;en;ID;)",
    "GarenaMSDK/4.0.40(Redmi Note 10;Android 12;en;ID;)",
    "GarenaMSDK/4.0.41(Poco X3;Android 11;en;SG;)",
    "GarenaMSDK/4.0.42(SM-S918B;Android 14;en;MY;)"
]
def random_ua(): return random.choice(UA_POOL)

def encode_varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n: b |= 0x80
        out.append(b)
        if not n: break
    return bytes(out)

def create_proto_field(field_num, value):
    if isinstance(value, int): return encode_varint((field_num << 3) | 0) + encode_varint(value)
    if isinstance(value, str):
        v = value.encode(); return encode_varint((field_num << 3) | 2) + encode_varint(len(v)) + v
    if isinstance(value, bytes): return encode_varint((field_num << 3) | 2) + encode_varint(len(value)) + value
    return b""

def build_proto(fields): return b"".join(create_proto_field(k, v) for k, v in fields.items())
def aes_encrypt_bytes(plain_bytes): return AES.new(_AES_KEY, AES.MODE_CBC, _AES_IV).encrypt(pad(plain_bytes, AES.block_size))

_KS14 = bytes([0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30])
def _make_field_f14(open_id):
    ob = open_id.encode("latin1", errors="ignore") if isinstance(open_id, str) else open_id
    return bytes((ob[i] ^ _KS14[i % 32]) for i in range(len(ob)))

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
def extract_jwt(content):
    try:
        m = JWT_RE.search(content.decode("utf-8", errors="ignore"))
        return m.group(0) if m else None
    except: return None

def _ga_sv(): return str(int(time.time()) - random.randint(0, 60))

def guest_register(session, password, timeout=(1, 3)):
    try:
        body = json.dumps({"app_id": APP_ID, "client_type": 2, "password": password, "source": 2}, separators=(",", ":"))
        sig = hmac.new(HEX_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
        headers = {"User-Agent": random_ua(), "Connection": "Keep-Alive", "Accept": "application/json", "Accept-Encoding": "gzip", "Authorization": f"Signature {sig}", "Content-Type": "application/json; charset=utf-8", "Host": "100067.connect.garena.com"}
        headers.update(get_ip_headers())
        r = session.post(URL_GUEST_REGISTER, headers=headers, data=body, timeout=timeout, verify=False)
        if r.status_code == 200:
            j = r.json()
            if j.get("code") == 0: return j["data"]["uid"]
    except: pass
    return None

def token_grant(session, uid, password, timeout=(1, 3)):
    try:
        body = json.dumps({"client_id": APP_ID, "client_secret": HEX_KEY, "client_type": 2, "device_id": f"02-{uuid.uuid4()}", "password": password, "response_type": "token", "uid": uid}, separators=(",", ":"))
        headers = {"User-Agent": random_ua(), "Connection": "Keep-Alive", "Accept": "application/json", "Accept-Encoding": "gzip", "Content-Type": "application/json; charset=utf-8", "Host": "100067.connect.garena.com"}
        headers.update(get_ip_headers())
        r = session.post(URL_TOKEN_GRANT, headers=headers, data=body, timeout=timeout, verify=False)
        if r.status_code == 200:
            j = r.json()
            if j.get("code") == 0: return j["data"]["access_token"], j["data"]["open_id"]
    except: pass
    return None

def build_majorlogin_proto(open_id, access_token, lang="en"):
    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    fields = {3: now_ts, 4: "free fire", 5: 4, 7: "1.132.1", 8: "2019116753", 9: "Android OS 13", 10: "Handheld", 11: "Samsung SM-A325M", 12: 1280, 13: 720, 14: "240", 15: "x86-64", 16: 6000, 17: "Adreno", 18: "OpenGL", 19: f"Google|{uuid.uuid4()}", 20: "127.0.0.1", 21: lang, 22: open_id, 23: "4", 24: "Handheld", 25: "Samsung", 26: "IND", 29: access_token, 30: 1, 41: "Jio", 42: "WIFI", 92: 20000, 93: "max", 97: 1, 98: 1, 99: "4", 100: "4", 104: 77149, 105: 1}
    return aes_encrypt_bytes(build_proto(fields))

def major_login(session, access_token, open_id, lang, timeout=(1, 3)):
    try:
        payload = build_majorlogin_proto(open_id, access_token, lang)
        headers = {"User-Agent": random_ua(), "Accept-Encoding": "deflate, gzip", "X-GA-SV": _ga_sv(), "Authorization": f"Bearer {access_token}", "X-GA": "v1 1", "ReleaseVersion": RELEASE_VER, "Content-Type": "application/octet-stream", "X-Unity-Version": "2018.4.12f1", "Host": "loginbp.ppmainecoonghj.com"}
        headers.update(get_ip_headers())
        r = session.post(URL_MAJOR_LOGIN, headers=headers, data=payload, verify=False, timeout=timeout)
        if r.status_code == 200 and len(r.content) >= 20:
            jwt = extract_jwt(r.content)
            account_id = None
            if jwt:
                try:
                    p = jwt.split(".")[1]; p += "=" * (4 - len(p) % 4)
                    dec = json.loads(base64.urlsafe_b64decode(p))
                    account_id = dec.get("account_id") or dec.get("external_id")
                except: pass
            if not account_id:
                nums = re.findall(r"\b\d{10,12}\b", r.content.decode("utf-8", errors="ignore"))
                if nums: account_id = nums[0]
            if account_id: return {"account_id": str(account_id), "jwt_token": jwt or ""}
    except: pass
    return None

def major_register(session, access_token, open_id, uid, password, region, nick, lang, timeout=(1, 3)):
    try:
        payload = {1: nick, 2: access_token, 3: open_id, 5: 102000007, 6: 4, 7: 1, 13: 1, 14: _make_field_f14(open_id), 15: lang, 16: 1, 17: 1, 22: FIELD_22}
        enc = aes_encrypt_bytes(build_proto(payload))
        headers = {"User-Agent": random_ua(), "Accept-Encoding": "deflate, gzip", "X-GA-SV": _ga_sv(), "Authorization": "Bearer", "X-GA": "v1 1", "ReleaseVersion": RELEASE_VER, "Content-Type": "application/x-www-form-urlencoded", "X-Unity-Version": "2018.4.12f1", "Host": "loginbp.ppmainecoonghj.com"}
        headers.update(get_ip_headers())
        session.post(URL_MAJOR_REGISTER, headers=headers, data=enc, verify=False, timeout=timeout)
        return major_login(session, access_token, open_id, lang, timeout)
    except: return None

def create_account(region, prefix):
    session = requests.Session()
    session.verify = False
    try:
        pw = secrets.token_hex(16)
        uid = guest_register(session, pw)
        if not uid: return None
        tok = token_grant(session, uid, pw)
        if not tok: return None
        at, oid = tok
        nick = f"{prefix[:4]}{''.join(random.choices(string.ascii_letters + string.digits, k=8))}"
        login = major_register(session, at, oid, uid, pw, region, nick, "id")
        if not login: return None
        return {
            "uid": uid, "password": pw, "name": nick,
            "account_id": login["account_id"], "region": region
        }
    except: return None
    finally: session.close()

# ═══════════════════════════════════════════════════════════════════════════
#  UI HTML (TEMA GALAXY)
# ═══════════════════════════════════════════════════════════════════════════
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard — IYAN'GTG</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg: #07080f;
            --panel: rgba(20, 22, 40, 0.65);
            --panel-solid: #12142a;
            --border: rgba(120, 130, 255, 0.18);
            --text: #e6e8ff;
            --muted: #8b90b8;
            --accent: #7c6cff;
            --accent2: #4fc3f7;
            --glow: 0 0 24px rgba(124, 108, 255, 0.35);
            --radius: 16px;
        }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            overflow-x: hidden;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        /* Galaxy background */
        .galaxy-bg {
            position: fixed; inset: 0; z-index: -1; overflow: hidden;
            background: radial-gradient(ellipse at 20% 10%, rgba(124, 108, 255, 0.15) 0%, transparent 50%),
                        radial-gradient(ellipse at 80% 90%, rgba(79, 195, 247, 0.15) 0%, transparent 50%);
        }
        .container {
            width: 100%; max-width: 600px; padding: 20px; z-index: 1;
        }
        .header {
            text-align: center; margin-bottom: 30px;
        }
        .header h1 { font-size: 28px; font-weight: 600; letter-spacing: 1px; }
        .header p { color: var(--muted); font-size: 14px; margin-top: 5px; }
        
        .panel {
            background: var(--panel);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5), var(--glow);
            margin-bottom: 20px;
        }
        
        .form-group { margin-bottom: 20px; }
        label { display: block; color: var(--muted); font-size: 13px; margin-bottom: 8px; font-weight: 500; }
        input, select {
            width: 100%; padding: 14px; background: var(--panel-solid);
            border: 1px solid var(--border); border-radius: 10px;
            color: var(--text); font-size: 15px; outline: none; transition: 0.3s;
        }
        input:focus, select:focus { border-color: var(--accent); box-shadow: 0 0 10px rgba(124, 108, 255, 0.2); }
        
        .btn {
            width: 100%; padding: 15px; background: linear-gradient(135deg, var(--accent), var(--accent2));
            color: #fff; border: none; border-radius: 10px; font-size: 16px; font-weight: 600;
            cursor: pointer; transition: 0.3s; box-shadow: 0 4px 15px rgba(124, 108, 255, 0.4);
        }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(124, 108, 255, 0.6); }
        .btn:disabled { background: var(--muted); box-shadow: none; cursor: not-allowed; transform: none; }
        
        .result-box {
            background: #000; border: 1px solid var(--border); border-radius: 10px;
            padding: 15px; font-family: monospace; font-size: 13px; color: #a0aec0;
            max-height: 250px; overflow-y: auto; display: none; margin-top: 20px; white-space: pre-wrap;
        }
        .loading { text-align: center; color: var(--accent); margin-top: 20px; display: none; font-weight: 500; }
        
        .toast {
            position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
            background: #10b981; color: white; padding: 12px 24px; border-radius: 50px;
            font-weight: 600; opacity: 0; transition: 0.3s; z-index: 100;
        }
        .toast.show { opacity: 1; bottom: 30px; }
    </style>
</head>
<body>
    <div class="galaxy-bg"></div>
    
    <div class="container">
        <div class="header">
            <h1>IYAN'GTG Generator</h1>
            <p>Web Galaxy Dashboard v5.0</p>
        </div>

        <div class="panel">
            <div class="form-group">
                <label>Jumlah Akun (Max 15)</label>
                <input type="number" id="count" value="1" min="1" max="15">
            </div>
            <div class="form-group">
                <label>Region</label>
                <select id="region">
                    <option value="ID">Indonesia (ID)</option>
                    <option value="SG">Singapore (SG)</option>
                    <option value="MY">Malaysia (MY)</option>
                    <option value="PH">Filipina (PH)</option>
                </select>
            </div>
            <div class="form-group">
                <label>Prefix Nama (Maks 4 Huruf)</label>
                <input type="text" id="prefix" value="IYN" maxlength="4">
            </div>
            <button class="btn" id="btnGen" onclick="startGen()">Generate Akun Sekarang</button>
            
            <div class="loading" id="loading">Sedang memproses... Mohon tunggu.</div>
            <div class="result-box" id="resultBox"></div>
            <button class="btn" id="copyBtn" style="display:none; margin-top:15px; background:#10b981;" onclick="copyResult()">Salin Data Akun</button>
        </div>
    </div>

    <div class="toast" id="toast">Data berhasil di-copy!</div>

    <script>
        let generatedData = "";

        async function startGen() {
            const count = document.getElementById('count').value;
            const region = document.getElementById('region').value;
            const prefix = document.getElementById('prefix').value || 'IYN';
            
            const btn = document.getElementById('btnGen');
            const loading = document.getElementById('loading');
            const resultBox = document.getElementById('resultBox');
            const copyBtn = document.getElementById('copyBtn');

            btn.disabled = true;
            loading.style.display = 'block';
            resultBox.style.display = 'none';
            copyBtn.style.display = 'none';

            try {
                const res = await fetch(`/xns?count=${count}&region=${region}&name=${prefix}`);
                const data = await res.json();

                if (data.success && data.accounts.length > 0) {
                    let textOutput = "";
                    data.accounts.forEach((acc, i) => {
                        textOutput += `[ Akun ${i+1} ]\\n`;
                        textOutput += `UID: ${acc.uid}\\n`;
                        textOutput += `Pass: ${acc.password}\\n`;
                        textOutput += `Nick: ${acc.name}\\n`;
                        textOutput += `Region: ${acc.region}\\n\\n`;
                    });
                    resultBox.innerText = textOutput;
                    generatedData = textOutput;
                    copyBtn.style.display = 'block';
                } else {
                    resultBox.innerText = "Gagal generate. Coba lagi atau kurangi jumlah.";
                }
            } catch (err) {
                resultBox.innerText = "Error: " + err.message;
            } finally {
                btn.disabled = false;
                loading.style.display = 'none';
                resultBox.style.display = 'block';
            }
        }

        function copyResult() {
            if(generatedData) {
                navigator.clipboard.writeText(generatedData).then(() => {
                    const toast = document.getElementById('toast');
                    toast.classList.add('show');
                    setTimeout(() => toast.classList.remove('show'), 2500);
                });
            }
        }
    </script>
</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route("/xns", methods=["GET"])
def generate_accounts():
    try: count = max(1, min(int(request.args.get("count", "1")), MAX_COUNT))
    except: count = 1
    region = request.args.get("region", FORCE_REGION).upper()
    name = request.args.get("name", "IYN")[:4] or "IYN"
    
    results = []
    args_list = [(region, name) for _ in range(count)]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(count, 5)) as executor:
        for res in executor.map(lambda args: create_account(*args), args_list):
            if res: results.append(res)
            if len(results) >= count: break

    return jsonify({"success": len(results) > 0, "total": len(results), "accounts": results})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)
