"""卡密清洗向量测试：既要修好脏输入，又必须对规范输入幂等（老卡不能失效）。"""
import sys
sys.path.insert(0, r'D:\XM\xprosu_fixed\_remote-snapshot')
sys.path.insert(0, r'D:\XM\xprosu_fixed\xprosu\XproSU-source-v1.1-99-deploy\server\gl-license')
from store import clean_card_key, normalize_card_key, card_hash
from crypto import sha256

CANON = 'AAAAA-BBBBB-CCCCC-DDDDD'
OLD_HASH = sha256(CANON.strip().upper()).hex()   # 旧实现（只 strip+upper）
FAIL = []


def chk(name, got, want):
    ok = got == want
    print(('PASS' if ok else 'FAIL'), name, '->', repr(got))
    if not ok:
        FAIL.append(name)


print('=== 1. 幂等：规范卡密必须原样 ===')
chk('规范卡密', normalize_card_key(CANON), CANON)
chk('小写规范', normalize_card_key(CANON.lower()), CANON)
chk('前后空格', normalize_card_key('  ' + CANON + '  '), CANON)
print('   旧哈希 == 新哈希 ?', card_hash(CANON) == OLD_HASH)
if card_hash(CANON) != OLD_HASH:
    FAIL.append('向后兼容：老卡哈希变了')

print()
print('=== 2. 全角污染（输入法）===')
full = '\uff21\uff21\uff21\uff21\uff21-\uff22\uff22\uff22\uff22\uff22-\uff23\uff23\uff23\uff23\uff23-\uff24\uff24\uff24\uff24\uff24'
chk('全角字母', normalize_card_key(full), CANON)
chk('全角连字符', normalize_card_key(CANON.replace('-', '\uff0d')), CANON)

print()
print('=== 3. 零宽 / 软连字符 ===')
chk('ZWSP 夹在中间', normalize_card_key('AAAAA\u200b-BBBBB-CCCCC-DDDDD'), CANON)
chk('BOM 开头', normalize_card_key('\ufeff' + CANON), CANON)
chk('ZWNJ+ZWJ', normalize_card_key('AAAAA-\u200cBBBBB-\u200dCCCCC-DDDDD'), CANON)
chk('软连字符', normalize_card_key('AAAAA-\u00adBBBBB-CCCCC-DDDDD'), CANON)

print()
print('=== 4. 连字符变体 ===')
for name, dash in [('en dash', '\u2013'), ('em dash', '\u2014'), ('minus', '\u2212'),
                   ('hyphen U+2010', '\u2010'), ('fullwidth', '\uff0d'), ('box', '\u2500')]:
    chk(name, normalize_card_key(CANON.replace('-', dash)), CANON)

print()
print('=== 5. 空白变体 ===')
chk('NBSP', normalize_card_key(CANON.replace('-', '\u00a0')), CANON)
chk('Tab', normalize_card_key('AAAAA\t-BBBBB-CCCCC-DDDDD'), CANON)
chk('换行', normalize_card_key('AAAAA-\nBBBBB-CCCCC-DDDDD'), CANON)

print()
print('=== 6. 漏打横杠 ===')
chk('20 位无横杠', normalize_card_key('AAAAABBBBBCCCCCDDDDD'), CANON)

print()
print('=== 7. 哈希一致性：脏输入 == 规范输入 ===')
same = card_hash(full) == card_hash(CANON)
print('   全角输入与规范输入同哈希 ?', same)
if not same: FAIL.append('脏输入哈希不一致')

print()
print('=== 8. 不能过度清洗（不同卡必须不同）===')
a = card_hash('AAAAA-BBBBB-CCCCC-DDDDD')
b = card_hash('AAAAA-BBBBB-CCCCC-DDDDE')
print('   相邻卡哈希不同 ?', a != b)
if a == b: FAIL.append('过度清洗导致碰撞')

print()
print('FAIL ' + str(len(FAIL)) if FAIL else 'ALL PASS')
print('失败项:', FAIL) if FAIL else None