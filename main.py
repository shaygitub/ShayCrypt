import cryptography
import hashlib
import os
from uuid import getnode
import random
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pyaes


def extract_ltr(st, stt):
    if stt:
        return st[-1], st[0: len(st) - 1], False
    return st[0], st[1:], True


def spec_ceasar(lowa, highz, lt, op, chngchr):
    if op:
        if chngchr + ord(lt) > ord(highz):
            return chr(ord(lowa) - 1 + chngchr - (ord(highz) - ord(lt)))
        else:
            return chr(ord(lt) + chngchr)
    else:
        if ord(lt) - chngchr < ord(lowa):
            return chr(ord(highz) + 1 - chngchr + (ord(lt) - ord(lowa)))
        else:
            return chr(ord(lt) - chngchr)


def get_fibi(index):
    if index == 0:
        return 0
    elif index == 1:
        return 1
    else:
        return get_fibi(index - 1) + get_fibi(index - 2)


def create_tname(target, targd):
    regtpl = [os.urandom(10), os.urandom(10)]
    return hashlib.pbkdf2_hmac('sha512', target.encode(), regtpl[0] + targd.encode() + regtpl[1], 5, dklen=None), regtpl


def create_prekey(tname):
    pk = ""
    mak = ':'.join(['{:02x}'.format((getnode() >> elements) & 0xff) for elements in range(0,8*6,8)][::-1])
    mst = True
    tnst = False

    while True:
        if mak != "":
            cl, mak, mst = extract_ltr(mak, mst)
            pk += cl
        else:
            break
        if tname != "":
            cl, tname, tnst = extract_ltr(tname, tnst)
            pk += cl
        else:
            break

    lo = mak
    lost = True
    if lo == "":
        lo = tname

    while True:
        if lo != "":
            cl, lo, lost = extract_ltr(lo, lost)
            pk += cl
        else:
            break

    return pk


def create_pstkey(prkey, name, mck):
    ln = len(mck)
    bdct = {}
    bbk = ""
    mind = 0
    for lt in name:
        if mck[mind % ln] in list(bdct.keys()):
            bdct[mck[mind % ln]] += int(ord(lt) / 16)
        else:
            bdct[mck[mind % ln]] = int(ord(lt) / 16)
        mind += 1

    mnum = 1
    while list(bdct.values()).count(0) != len(bdct):
        plst = [x[0] for x in list(bdct.items()) if x[1] != 0]
        for k in plst:
            if plst.index(k) % mnum == 0:
                bbk += plst[plst.index(k)]
                bdct[plst[plst.index(k)]] -= 1
        mnum += 1
        if mnum > len([x[0] for x in list(bdct.items()) if x[1] != 0]):
            mnum = 1

    #print(bbk)
    curop = True
    lwhgh = True
    bk = ""
    cnt = 0
    for ch in bbk:
        if 'a' <= ch <= 'z':
            bk += spec_ceasar('a', 'z', ch, curop, get_fibi(cnt) % 26)

        elif'A' <= ch <= 'Z':
            bk += spec_ceasar('A', 'Z', ch, curop, get_fibi(cnt) % 26)

        else:
            if curop:
                if lwhgh:
                    bk += chr(ord('z') - (get_fibi(cnt) % 26))
                else:
                    bk += chr(ord('Z') - (get_fibi(cnt) % 26))
            else:
                if lwhgh:
                    bk += chr(ord('a') + (get_fibi(cnt) % 26))
                else:
                    bk += chr(ord('A') + (get_fibi(cnt) % 26))
            if lwhgh:
                lwhgh = False
            else:
                lwhgh = True

        if curop:
            curop = False
        else:
            curop = True

        if cnt < 30:
            cnt += 1
        else:
            cnt = 0

    hsh = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hsh.update((prkey + bk).encode())
    return hsh.finalize()


def create_dkey(tname):
    favorites = "pKGNkzSuc3EB7qxftUMoyn0CWjIrs5lYiHZgDaQPV8mFL14J9RdAbeX2OvTh6w-_+=)(*&^%$#@!~`,<.>/?';:[{]}\\|"
    dk = ""
    for c in tname:
        try:
            if c != " ":
                dk += str(favorites.index(c))
        except:
            dk += favorites[ord(c) % len(favorites)]
    dsh = hashes.Hash(hashes.SHA256(), backend=default_backend())
    dsh.update(dk.encode())
    return dsh.finalize()


def shay_encrypt(n, c, dt):
    if dt == "":
        dt = "By1$#ENDOFDATA#"
    tn, tpl = create_tname(n, c)
    tn = str(tn)
    pk = create_prekey(tn)
    actkey = create_pstkey(pk, tn, ':'.join(
        ['{:02x}'.format((getnode() >> elements) & 0xff) for elements in range(0, 8 * 6, 8)][::-1]))
    print(':'.join(
        ['{:02x}'.format((getnode() >> elements) & 0xff) for elements in range(0, 8 * 6, 8)][::-1]))
    dk = create_dkey(tn)
    cipher = Cipher(algorithms.AES(dk),
                    modes.CBC((':'.join(['{:02x}'.format((getnode() >> elements) & 0xff) for elements in
                                         range(0, 8 * 6, 8)][::-1])).replace(":", "", 1).encode()),
                    backend=default_backend())
    pdd = padding.PKCS7(128).padder()
    pddt = pdd.update(dt.encode()) + pdd.finalize()
    crypt = cipher.encryptor()
    eodata = crypt.update(pddt) + crypt.finalize()
    print(eodata)
    cipher = Cipher(algorithms.AES(actkey),
                    modes.CBC((':'.join(['{:02x}'.format((getnode() >> elements) & 0xff) for elements in
                                         range(0, 8 * 6, 8)][::-1])).replace(":", "", 1).encode()),
                    backend=default_backend())
    pdd = padding.PKCS7(128).padder()
    pddt = pdd.update(eodata) + pdd.finalize()
    crypt = cipher.encryptor()
    etdata = crypt.update(pddt) + crypt.finalize()
    return etdata, tpl


def get_tnd(t, c, lst):
    return hashlib.pbkdf2_hmac('sha512', t.encode(), lst[0] + c.encode() + lst[1], 5, dklen=None)


def shay_decrypt(encd, tpl, t, d, kt):
    mf = create_pstkey(create_prekey(str(get_tnd(t, d, tpl))), str(get_tnd(t, d, tpl)), kt)
    ntnmk = create_dkey(str(get_tnd(t, d, tpl)))
    cp = Cipher(algorithms.AES(mf), modes.CBC((kt.replace(":", "", 1).encode())), backend=default_backend())  # TODO PROBLEM HERE
    cr = cp.decryptor()
    eodata = cr.update(encd)
    cp = Cipher(algorithms.AES(ntnmk), modes.CBC((kt.replace(":", "", 1).encode())), backend=default_backend())
    cr = cp.decryptor()
    ezdata = cr.update(eodata)
    return ezdata.split(b'#ENDOFDATA#')[0]


def main():
    ed, tpl = shay_encrypt(input("n ->"), input("c ->"), input("d (32=default) ->"))
    print(f'ed -> {ed}, {tpl}')
    print(shay_decrypt(ed, tpl, input("n ->"), input("c ->"), input("kt ->")))
    return ed, tpl


if __name__ == "__main__":
    main()
