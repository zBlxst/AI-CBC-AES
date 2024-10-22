from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1
from Crypto.Cipher import AES

from functools import reduce
import time

BLOCK_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16

debug = True

base_time = time.time() 
def print_time(message = "From the beggining"):
    if print_time.printing:
        print(f"{message:20s} : {time.time() - base_time:.4f}s")
print_time.printing = True

def bytes_to_blocks(b):
    return [b[BLOCK_SIZE*i:BLOCK_SIZE*(i+1)] for i in range(len(b)//BLOCK_SIZE)]

def xor_block(b1, b2):
    return (int.from_bytes(b1, 'big') ^ int.from_bytes(b2, 'big')).to_bytes(BLOCK_SIZE, 'big')

def incr_bloc(b):
    return (int.from_bytes(b, 'big') + 1).to_bytes(BLOCK_SIZE, 'big')

def pad(b):
    size = BLOCK_SIZE - len(b) % BLOCK_SIZE
    return b + size.to_bytes(1, 'big')*size

def unpad(b):
    size = b[-1]
    assert len(b) % BLOCK_SIZE == 0 # Checks if b is correctly padded
    assert b[-size:] == bytes([size]*size) # Checks if b is correctly padded
    return b[:-size]

def gen_key(pwd, iv):
    all_ = PBKDF2(pwd, salt=iv, dkLen=80, count=10000, hmac_hash_module=SHA1)
    return all_[:KEY_SIZE], all_[KEY_SIZE:2*KEY_SIZE], all_[2*KEY_SIZE:] # Divided all in three parts to recover K1, K2 and R

def encrypt_block(k, m):
    return AES.new(k, AES.MODE_EBC).encrypt(m)

def decrypt_block(k, m):
    return AES.new(k, AES.MODE_EBC).decrypt(m)

def encrypt_iacbc(k1, k2, r, m):

    # Compute the amount of block to encrypt
    size = len(m) // BLOCK_SIZE
    print_time("[Encrypt] Size")

    # The values of R+i
    ris = b"".join([(int.from_bytes(r, 'big')+i).to_bytes(BLOCK_SIZE, 'big') for i in range(size)])
    print_time("[Encrypt] Ri's")

    
    # The values of s_i
    sis = AES.new(k2, AES.MODE_ECB).encrypt(ris)
    print_time("[Encrypt] Si's")


    # We shift setup the s_i's to perform a single xor
    to_xor = b"\x00"*BLOCK_SIZE + b"".join([bytes_to_blocks(sis)[(i+1)%size] for i in range(size)])
    print_time("[Encrypt] To xor")
    

    checksum = reduce(xor_block, bytes_to_blocks(m), b"")
    to_encrypt = m + checksum
    print_time("[Encrypt] Checksum")


    # The encryption of R works exactly like an IV in CBC mode
    iv = AES.new(k1, AES.MODE_ECB).encrypt(r)
    print_time("[Encrypt] IV")

    encrypted = AES.new(key=k1, iv=iv, mode=AES.MODE_CBC).encrypt(to_encrypt)
    print_time("[Encrypt] Encrypted")


    return iv + b"".join([xor_block(bytes_to_blocks(encrypted)[i], bytes_to_blocks(to_xor)[i]) for i in range(size+1)])

def decrypt_iacbc(k1, k2, r, c):

    # Separate the IV and the ciphertext
    iv, c = c[:IV_SIZE], c[IV_SIZE:]

    # Compute the amount of blocks of the cleartext
    size = len(c) // BLOCK_SIZE - 1
    print_time("[Decrypt] Size")

    # The values of R+i
    ris = b"".join([(int.from_bytes(r, 'big')+i).to_bytes(BLOCK_SIZE, 'big') for i in range(size)])
    print_time("[Decrypt] Ri's")
    
    # The values of s_i
    sis = AES.new(k2, AES.MODE_ECB).encrypt(ris)
    print_time("[Decrypt] Si's")

    # We shift setup the s_i's to perform a single xor
    to_xor = b"\x00"*BLOCK_SIZE + b"".join([bytes_to_blocks(sis)[(i+1)%size] for i in range(size)])
    print_time("[Decrypt] To xor")


    to_decrypt = b"".join([xor_block(bytes_to_blocks(c)[i], bytes_to_blocks(to_xor)[i]) for i in range(size+1)])
    print_time("[Decrypt] To decrypt")


    decrypted = AES.new(k1, AES.MODE_CBC, iv=iv).decrypt(to_decrypt)
    print_time("[Decrypt] Decrypted")


    checksum = reduce(xor_block, [bytes_to_blocks(decrypted)[i] for i in range(size)], b"")
    print_time("[Decrypt] Checksum")


    assert checksum == bytes_to_blocks(decrypted)[-1]
    return b"".join(bytes_to_blocks(decrypted)[:-1])

def encrypt(pwd, iv, m):
    k1, k2, r = gen_key(pwd, iv)
    return encrypt_iacbc(k1, k2, r, pad(m))

def decrypt(pwd, iv, c):
    k1, k2, r = gen_key(pwd, iv)
    return unpad(decrypt_iacbc(k1, k2, r, c))

class Params:
    def __init__(self, enc, pwd, iv, input, output):
        self.enc = enc
        self.pwd = pwd
        self.iv = iv
        self.input = input
        self.output = output

def run(params):
    with open(params.input, "rb") as f:
        content = b""
        read = f.read()
        while read != b"":
            content += read
            read = f.read()
        # print(content)

    if params.enc:
        to_write = encrypt(params.pwd, params.iv, content)
    else:
        to_write = decrypt(params.pwd, params.iv, content)

    with open(params.output, "wb") as f:
        f.write(to_write)

