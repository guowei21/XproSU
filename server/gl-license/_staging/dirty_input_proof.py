import hashlib, json, struct, sys, urllib.request, urllib.error
sys.path.insert(0, '/app')
import crypto, wire
from store import CardStore, card_hash, normalize_card_key

store = CardStore('/app/cards.db')
BASE = 'http://127.0.0.1:8787'


def post(path, entries):
    body = wire.encode(wire.KIND_REQUEST, 0, entries)
    req = urllib.request.Request(BASE + path, data=body, headers={'Content-Type': 'application/octet-stream'}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        raw = e.read()
    code = struct.unpack_from('<H', raw, 6)[0]
    d = wire.decode(raw)
    return code, (d[1] if d else {})


def to_fullwidth(s):
    out = []
    for c in s:
        if 'A' <= c <= 'Z':
            out.append(chr(0xFF21 + ord(c) - ord('A')))
        elif c == '-':
            out.append('\uff0d')
        else:
            out.append(c)
    return ''.join(out)


def to_fullwidth_digits(s):
    out = []
    for c in s:
        if '2' <= c <= '7':
            out.append(chr(0xFF12 + ord(c) - ord('2')))
        elif c == '-':
            out.append('\uff0d')
        else:
            out.append(c)
    return ''.join(out)


CASES = [
    ('规范（对照）', lambda c: c),
    ('全角字母', to_fullwidth),
    ('全角数字', to_fullwidth_digits),
    ('全角连字符', lambda c: c.replace('-', '\uff0d')),
    ('en dash', lambda c: c.replace('-', '\u2013')),
    ('em dash', lambda c: c.replace('-', '\u2014')),
    ('minus sign', lambda c: c.replace('-', '\u2212')),
    ('ZWSP 污染', lambda c: c[:5] + '\u200b' + c[5:]),
    ('BOM 开头', lambda c: '\ufeff' + c),
    ('ZWNJ/ZWJ', lambda c: c.replace('-', '\u200c-\u200d', 1)),
    ('软连字符', lambda c: c.replace('-', '\u00ad-', 1)),
    ('NBSP 代替横杠', lambda c: c.replace('-', '\u00a0')),
    ('Tab 分隔', lambda c: c.replace('-', '\t')),
    ('换行分隔', lambda c: c.replace('-', '\n')),
    ('漏打横杠', lambda c: c.replace('-', '')),
    ('前后加空格', lambda c: '  ' + c + '  '),
]

ok = 0
cards = []
for i, (name, dirty_fn) in enumerate(CASES):
    card = store.gen_cards(1, 1, batch='dirty-input', note='normalize')[0]
    cards.append(card)
    dirty = dirty_fn(card)
    fp = hashlib.sha256(('dirty-device-%d' % i).encode()).digest()
    _, pub = crypto.p256_generate_keypair()
    code, f = post('/api/activate', [
        (wire.TAG_CARD, dirty.encode('utf-8')),
        (wire.TAG_DEVICE_FP, fp.hex().encode()),
        (wire.TAG_PUBKEY, pub.hex().encode()),
        (wire.TAG_APP_VER, b'1.1-dirty'),
    ])
    good = code == 0
    if good:
        ok += 1
    print('  %-16s len=%-3d -> %s' % (name, len(dirty), 'PASS' if good else 'FAIL(code=%d)' % code))

print()
print('脏输入通过: %d/%d' % (ok, len(CASES)))
for c in cards:
    h = card_hash(normalize_card_key(c))
    store.delete_card(h)
    with store._connect() as conn:
        conn.execute('DELETE FROM activation_audit WHERE card_hash=?', (h,))
print('cleanup done')