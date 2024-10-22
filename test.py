from sys import argv
from encrypt import *
from random import randbytes
import os

pwd, iv = randbytes(100), randbytes(100)
for el in os.listdir("test/"):
    if el.endswith(".enc") or el.endswith(".dec"):
        continue
    params = Params(True, pwd, iv, "test/" + el, "test/" + el + ".enc")
    run(params)
    print()

for el in os.listdir("test/"):
    if not el.endswith(".enc") or el.endswith(".dec"):
        continue
    params = Params(False, pwd, iv, "test/" + el, "test/" + el + ".dec")
    run(params)
    print()

for el in os.listdir("test/"):
    if el.endswith(".enc") or el.endswith(".dec"):
        continue
    with open("test/"+el, "rb") as f:
        content_clear = b""
        read = f.read()
        while read != b"":
            content_clear += read
            read = f.read()

    with open("test/"+el+".enc.dec", "rb") as f:
        content_dec = b""
        read = f.read()
        while read != b"":
            content_dec += read
            read = f.read()

    assert(content_clear == content_dec)
    print()