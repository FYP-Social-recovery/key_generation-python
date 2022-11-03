import bip39 
import random
from coincurve import PrivateKey
from bip44 import Wallet
from bip44.utils import get_eth_addr
from bip32 import BIP32, HARDENED_INDEX
bip32 = BIP32.from_seed(bytes.fromhex("01"))


#generate the random value 
rand = random.getrandbits(128)
print("Random number ",rand)

#convert the random value into byte array
def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])


def access_bit(data, num):
    base = int(num // 8)
    shift = int(num % 8)
    return (data[base] >> shift) & 0x1

def byte_to_bit(seed):
    bitSeed=""
    for i in range(len(seed)*8):
        bitSeed=bitSeed+str(access_bit(seed,i))
    return bitSeed
print(hex(int(byte_to_bit(bip32.privkey), 2)))

entropy= bitstring_to_bytes(bin(rand))
print("entropy in byte array:::",entropy)
#generate mnemonic words 
mnemonic =bip39.encode_bytes(entropy)
print("mnemonic-words:::",mnemonic)

#generate 512 bit seed
seed= bip39.phrase_to_seed(mnemonic)

print("512 bit seed::",byte_to_bit(seed))

#generate seed using the mnemonic 
d= bip39.decode_phrase(mnemonic)
print("regenerated entropy using the mnemonic",d)

# #generate entropy using the mnemonic
# entropy= bip39.get_entropy_bits(12)
# print(entropy)


passphrase="12345"
w=Wallet(mnemonic,"english",passphrase)
sk, pk = w.derive_account("eth", account=0)
# sk = PrivateKey(sk)
privateKey=hex(int(byte_to_bit(sk), 2))
publicKey=hex(int(byte_to_bit(pk), 2))
print("private key of the wallet ",privateKey)
print("public key of the wallet",publicKey)

address= get_eth_addr(pk)
print(address)
