#!/usr/bin/env python3
"""
过 InfinityFree / rf.gd 类 JS 质询，拿到真实页面。
原理：服务端先返回加密 JS，要求用 slowAES 算出 cookie(__test) 再带回去。
这里纯 Python 复刻 slowAES(AES-128-CBC) 把 cookie 算出来，不伪造任何协议头。
用法: python3 solve.py <URL>
"""
import sys, re, time, urllib.request, urllib.error

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

# ---------- AES-128 基础 ----------
SBOX = [
99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22
]
RSBOX = [
82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37,114,248,246,100,134,104,152,22,212,164,92,204,93,101,182,146,108,112,72,80,253,237,185,218,94,21,70,87,167,141,157,132,144,216,171,0,140,188,211,10,247,228,88,5,184,179,69,6,208,44,30,143,202,63,15,2,193,175,189,3,1,19,138,107,58,145,17,65,79,103,220,234,151,242,207,206,240,180,230,115,150,172,116,34,231,173,53,133,226,249,55,232,28,117,223,110,71,241,26,113,29,41,197,137,111,183,98,14,170,24,190,27,252,86,62,75,198,210,121,32,154,219,192,254,120,205,90,244,31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125
]
RCON = [1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47,94,188,99,198,151,53,106,212,179,125,250,239,197,145,57,114,228,211,189,97,194,159,37,74,148,51,102,204,131,29,58,116,232,203,141,1]

def xtime(a):
    a <<= 1
    if a & 0x100: a ^= 0x11B
    return a & 0xFF

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        a = xtime(a); b >>= 1
    return p & 0xFF

def key_expansion(key):
    Nk = 4; Nr = 10
    w = []
    for i in range(Nk):
        w.append(list(key[4*i:4*i+4]))
    for i in range(Nk, 4*(Nr+1)):
        temp = list(w[i-1])
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[x] for x in temp]
            temp[0] ^= RCON[i//Nk - 1]
        w.append([w[i-Nk][j] ^ temp[j] for j in range(4)])
    return w

def add_round_key(state, w, rnd):
    for c in range(4):
        for r in range(4):
            state[r + 4*c] ^= w[rnd*4 + c][r]

def inv_shift_rows(s):
    ns = [0]*16
    for r in range(4):
        for c in range(4):
            ns[r + 4*((c+r) % 4)] = s[r + 4*c]
    return ns

def inv_sub_bytes(s):
    return [RSBOX[b] for b in s]

def inv_mix_columns(s):
    out = [0]*16
    for c in range(4):
        col = s[4*c:4*c+4]
        out[4*c+0] = gmul(col[0],14) ^ gmul(col[1],11) ^ gmul(col[2],13) ^ gmul(col[3],9)
        out[4*c+1] = gmul(col[0],9)  ^ gmul(col[1],14) ^ gmul(col[2],11) ^ gmul(col[3],13)
        out[4*c+2] = gmul(col[0],13) ^ gmul(col[1],9)  ^ gmul(col[2],14) ^ gmul(col[3],11)
        out[4*c+3] = gmul(col[0],11) ^ gmul(col[1],13) ^ gmul(col[2],9)  ^ gmul(col[3],14)
    return out

def decrypt_block(block, key):
    state = list(block)
    w = key_expansion(key)
    Nr = 10
    add_round_key(state, w, Nr)
    for rnd in range(Nr-1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        add_round_key(state, w, rnd)
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    add_round_key(state, w, 0)
    return state

def to_hex(arr):
    return ''.join('%02x' % b for b in arr)

def to_numbers(s):
    return [int(s[i:i+2], 16) for i in range(0, len(s), 2)]

# ---------- 网络 + 重试 ----------
def fetch(url, retries=12, timeout=30):
    last = None
    for _ in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            return urllib.request.urlopen(req, timeout=timeout).read()
        except Exception as e:
            last = e
            time.sleep(2)
    raise last

def main():
    if len(sys.argv) < 2:
        print("usage: solve.py <URL>"); sys.exit(1)
    base = sys.argv[1].rstrip('/')
    print(f"[1/3] 取挑战页 {base}/")
    html = fetch(base + '/').decode('utf-8', 'ignore')
    hexes = re.findall(r'toNumbers\("([0-9a-f]+)"\)', html)
    if len(hexes) < 3:
        print("::error::未检测到 JS 挑战，可能页面结构变了")
        sys.exit(1)
    a, b, c = to_numbers(hexes[0]), to_numbers(hexes[1]), to_numbers(hexes[2])

    print("[2/3] 拉 aes.js 并算 __test cookie")
    fetch(base + '/aes.js')  # 触发下载（结果不重要，cookie 只用 a/b/c 算）
    # slowAES.decrypt(c, CBC=2, a=key, b=iv) 单块: plaintext = AES_decrypt(c, key=a) XOR iv=b
    dec = decrypt_block(c, a)
    cookie = to_hex([dec[i] ^ b[i] for i in range(16)])
    print(f"     __test = {cookie}")

    print(f"[3/3] 带 cookie 取真页面 {base}/?i=1")
    last_err = None
    for _ in range(12):
        try:
            req = urllib.request.Request(base + '/?i=1', headers={"User-Agent": UA, "Cookie": "__test=" + cookie})
            resp = urllib.request.urlopen(req, timeout=30)
            body = resp.read()
            code = resp.status
            print(f"     HTTP {code}, 字节数 {len(body)}")
            if code == 200 and len(body) > 200:
                print("--- 真页面前 300 字节 ---")
                print(body[:300].decode('utf-8', 'ignore'))
                print("OK")
                return
            last_err = f"code={code} size={len(body)}"
        except Exception as e:
            last_err = str(e)
        time.sleep(2)
    print(f"::error::取真页面失败: {last_err}")
    sys.exit(1)

if __name__ == "__main__":
    main()
