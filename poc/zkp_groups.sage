from sagelib.groups import GroupP384
from util import to_bytes

G = GroupP384()

context_string = "ZKPV1-P384"

def hash_to_group(x, info):
    dst = to_bytes("HashToGroup-") + to_bytes(context_string) + info
    return G.hash_to_group(x, dst)

def hash_to_scalar(x, info):
    dst = to_bytes("HashToScalar-") + to_bytes(context_string) + info
    return G.hash_to_scalar(x, dst)

Gs = [hash_to_group(to_bytes("gen"), to_bytes(f"{i}")) for i in range(100)]
