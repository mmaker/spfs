from sagelib.groups import GroupP384
import struct

G = GroupP384()

context_string = b"ZKPV1-P384"

def hash_to_group(x, info: bytes):
    dst = b"HashToGroup-" + context_string + info
    return G.hash_to_group(x, dst)

def hash_to_scalar(x, info):
    dst = b"HashToScalar-" + context_string + info
    return G.hash_to_scalar(x, dst)

GenG = G.generator()
GenH = hash_to_group(G.serialize([GenG]), b"generatorH")
Gs = [hash_to_group(b"gen", struct.pack('<Q', i)) for i in range(100)]
