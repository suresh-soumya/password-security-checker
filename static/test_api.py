import sys, io, requests
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

def test(pw, label=""):
    r = requests.post("http://127.0.0.1:5000/analyze", json={"password": pw})
    d = r.json()
    print(f"\n=== {label or repr(pw)} ===")
    print(f"  Score    : {d['score']['total']}/100  Grade: {d['score']['grade']}")
    print(f"  Strength : {d['strength']['label']}")
    print(f"  BF time  : {d['brute_force_crack_time']}")
    print(f"  RW time  : {d['real_world_crack_time']}")
    print(f"  Patterns : {[w['code'] for w in d['patterns']['warnings']]}")
    print(f"  Critical : {d['patterns']['has_critical']}")
    print(f"  Breach   : found={d['breach']['found']} count={d['breach']['count']}")
    bd = d['score']['breakdown']
    print(f"  Breakdown: len={bd['length']['pts']} div={bd['diversity']['pts']} ent={bd['entropy']['pts']} breach={bd['breach']['pts']}")
    explain = [e['text'] for e in d['score']['explanation'][:3]]
    print(f"  Explain  : {explain}")

test("password123",    "very common password")
test("admin",          "super common + too short")
test("aaaaaaaa",       "repeated chars")
test("qwerty123",      "keyboard walk + digits")
test("Tr0ub4dor&3",   "medium passphrase-style")
test("X7#mK2pQw9vLn", "random strong no breach")
test("X7#mK2$pQw9!vLn8@zR3", "very long strong random")
