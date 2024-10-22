from sys import argv
from encrypt import *
from random import randbytes
import os

# This is just for testing
# Put some files into the test folder
# It will encrypt all files and add the extension .enc
# The it will decrypt all files and add the extension .dec
# Then it will compare the clear files with the decrypted files and assert the equality
# This takes someting like 6 seconds for a 50kb file.

pwd, iv = randbytes(100), randbytes(100)

# Encrypt everything
for el in os.listdir("test/"):
    if el.endswith(".enc") or el.endswith(".dec"):
        continue
    print(f"Encrypting {'test/' + el}")
    params = Params(True, pwd, iv, "test/" + el, "test/" + el + ".enc")
    run(params)
    print()

# Decrypt everything
for el in os.listdir("test/"):
    if not el.endswith(".enc"):
        continue
    print(f"Decrypting {'test/' + el}")
    params = Params(False, pwd, iv, "test/" + el, "test/" + el + ".dec")
    run(params)
    print()


# Compare everything 
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

    # If any file is different, AssertionError
    assert(content_clear == content_dec)