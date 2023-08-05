import os
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import codecs
import hashlib
import base64


def getall_jumps(favs, ofs, mnt, dr):
    fsi = favs.index(ofs)
    if ofs == ".":
        while fsi > 7:
            ofs += favs[fsi - 7]
            fsi -= 7
    else:
        if not dr:
            while fsi <= len(favs) - 1 - mnt:
                ofs += favs[fsi + mnt]
                fsi += mnt
        else:
            while fsi > mnt:
                ofs += favs[fsi - mnt]
                fsi -= mnt
    return ofs


def create_sgn(favs, ktv, pr):
    sg = ""
    kti = 0
    for lt in ktv:
        sg += getall_jumps(favs, lt, int(pr[kti % len(pr)]), ord(lt) % 3 == int(pr[kti % len(pr)]) % 2)
        kti += 1

    hsh = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hsh.update(favs.encode())
    cp = Fernet(base64.b64encode(hsh.finalize()))
    ssg = cp.encrypt(sg.encode())
    return hashlib.pbkdf2_hmac('sha512', favs.encode(), b'~|\\~-' + ssg + b'~\\-|~', 5, dklen=None)


def crsz(szhsh):
    psbl = b''
    chsh = 0
    while psbl != szhsh:
        hsh = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hsh.update(str(chsh).encode())
        psbl = hsh.finalize()
        chsh += 1
    return chsh


def close_cnt(rcvr, sndr, msg):
    print(msg)
    rcvr.close()
    sndr.close()


def receiver(port):
    favorites = "pKGNkzSuc3EB7qxftUMoyn0CWjIrs5lYiHZgDaQPV8mFL14J9RdAbeX2OvTh6w-_+=)(*&^%$#@!~`,<.>/?';:[{]}\\|"
    ip = socket.gethostbyname(socket.gethostname())
    sgn = create_sgn(favorites, ip, str(port))
    rcvr = socket.socket()

    print(f'Actual signature-> {sgn}')
    print(f'IP (make sure that sender knows)-> {ip}')

    rcvr.bind(("0.0.0.0", port))
    print("Waiting for sender to connect..")
    rcvr.listen(1)
    sndr, addr = rcvr.accept()
    print(f"Sender's data: {addr}")

    try:
        ssgn = sndr.recv(64)
        if ssgn == sgn:  # wrong signature
            close_cnt(rcvr, sndr, f"Sender {addr}'s signature was incorrect (actual: {sgn}, senders: {ssgn}, closing connection..")
            return
        print(f"Sender {addr} correct signature")

        sd = sndr.recv(100)  # name + ~\-|~ + desktop name + ~|\~- + mac of sender
        if len(sd) < 29 or sd.count(b'~\\-|~') + sd.count(b'~|\\~-') < 2 or sd.index(b'~\\-|~') > sd.index(b'~|\\~-'):   # wrong size of info message or not correct splitting
            close_cnt(rcvr, sndr, f"Sender {addr}'s syntax of initial message was wrong, closing connection..")
            return

        sn = (sd.split(b'~\\-|~')[0])
        sdn = str(sd.split(b'~\\-|~')[1].split(b'~|\\~-')[0])
        smck = str(sd.split(b'~|\\~-')[1])
        print(f'Sender {addr}:\n'
              f'Name of target-> {sn}\n'
              f'Desktop/PC name of target-> {sdn}\n'
              f'MAC of sender (encryptor)-> {smck}')

        if smck.count(":") != 3 or not smck.split(":")[0] == smck.split(":")[0] == smck.split(":")[0] == smck.split(":")[0] == 2:
            close_cnt(rcvr, sndr, f"Sender {addr}'s MAC syntax was wrong, closing connection..")
            return



    except socket.error as e:
        close_cnt(rcvr, sndr, f'Socket error with sender {addr}: {e}')
        return
    print(f"Sender {addr} correct initial message")

    csz = crsz(sndr.recv(32))
    cdt = sndr.recv(csz)


def main():
    receiver(12345)


if __name__ == "__main__":
    main()
