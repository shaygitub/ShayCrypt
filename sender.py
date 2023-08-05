import os
import cryptography
import socket
import time
import hashlib
import codecs
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
from uuid import getnode


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


def close_cnt(sndr, msg):
    print(msg)
    sndr.close()


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


def create_init():
    n = input("Write name of target-> ").encode()
    d = input("Write desktop/PC name of target-> ").encode()
    return input("Write name of target-> ").encode() + b'~\\-|~' + input("Write desktop/PC name of target-> ").encode() +\
        b'~|\\~-' + ':'.join(['{:02x}'.format((getnode() >> elements) & 0xff) for elements in range(0, 8*6, 8)][::-1]).encode()


def sender(ip, port):
    favorites = "pKGNkzSuc3EB7qxftUMoyn0CWjIrs5lYiHZgDaQPV8mFL14J9RdAbeX2OvTh6w-_+=)(*&^%$#@!~`,<.>/?';:[{]}\\|"
    pdt = input("Write data to encrypt and send-> ")
    sndr = socket.socket()
    try_cnt = 0
    while True:
        try:
            if try_cnt > 10:
                print(f"Receiver not receiving after 10 tries, exiting program..")
                return
            sndr.connect((ip, port))
            break

        except:
            print("Waiting for receiver to start listening..")
            try_cnt += 1
            time.sleep(3)

    print(f'Connected to receiver ({ip}, {port})!')
    ssg = create_sgn(favorites, ip, str(port))
    print(f'Created signature-> {ssg}, length in bytes-> {len(ssg)}')

    try:
        sndr.send(ssg)
        print(f'Initial message-> {create_init()}')
        sndr.send(create_init())

    except socket.error as e:
        close_cnt(sndr, f'Socket error (either problem with receiver/ incorrect data was sent): {e}')
        return


def main():
    sender("192.168.1.35", 12345)


if __name__ == "__main__":
    main()


