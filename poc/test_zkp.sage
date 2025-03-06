#!/usr/bin/sage
# vim: syntax=python

from sagelib.arc_groups import GroupP384, hash_to_group
from sagelib.zkp import GroupMorphismPreimage, prove_batchable, verify_batchable
from sagelib.test_drng import TestDRNG
from util import to_hex, to_bytes
from sagelib.sho import Shake128GroupP384


def discrete_logarithm(path="vectors"):
    """
    Proves the following statement:

        DL(X) = PoK{(x): X = x * G}

    """
    group = GroupP384()
    rng = TestDRNG("test vector seed".encode('utf-8'))
    G = group.generator()
    x = group.random_scalar(rng)
    X = G * x

    statement = GroupMorphismPreimage(group)
    [var_x] = statement.allocate_scalars(1)
    statement.append_equation(X, [(var_x, G)])

    proof = prove_batchable(rng, b"test", statement, [x], group)
    print(f"Proof: {to_hex(proof)}")
    assert verify_batchable(b"test", statement, proof, group)

def dleq(path="vectors"):
    """
    Proves the following statement:

        DLEQ(G, H, X, Y) = PoK{(x): X = x * G, Y = x * H}

    """
    group = GroupP384()
    rng = TestDRNG("test vector seed".encode('utf-8'))
    G = group.generator()
    H = group.random(rng)
    x = group.random_scalar(rng)
    X = G * x
    Y = H * x

    statement = GroupMorphismPreimage(group)
    [var_x] = statement.allocate_scalars(1)
    statement.append_equation(X, [(var_x, G)])
    statement.append_equation(Y, [(var_x, H)])

    proof = prove_batchable(rng, b"test", statement, [x], group)
    print(f"Proof: {to_hex(proof)}")
    assert verify_batchable(b"test", statement, proof, group)


def pedersen_commitment(path="vectors"):
    """
    Proves the following statement:

        PEDERSEN(G, H, C) = PoK{(x, r): C = x * G + r * H}
    """
    group = GroupP384()
    rng = TestDRNG("test vector seed".encode('utf-8'))
    G = group.generator()
    H = group.random(rng)
    x = group.random_scalar(rng)
    r = group.random_scalar(rng)

    C = G * x + H * r
    statement = GroupMorphismPreimage(group)
    var_x, var_r = statement.allocate_scalars(2)
    statement.append_equation(C, [(var_x, G), (var_r, H)])
    proof = prove_batchable(rng, b"test", statement, [x, r], group)
    print(f"Proof: {to_hex(proof)}")
    assert verify_batchable(b"test", statement, proof, group)



def pedersen_commitment_dleq(path="vectors"):
    """
    Proves the following statement:

        PEDERSEN(G0, G1, G2, G3, X, Y) = PoK{(x0, x1):  X = x0 * G0  + x1 * G1, Y = x0 * G2 + x1 * G3}
    """
    group = GroupP384()
    Gs = [hash_to_group(to_bytes("gen"), to_bytes(f"{i}")) for i in range(100)]

    rng = TestDRNG("test vector seed".encode('utf-8'))

    witness = [group.random_scalar(rng) for i in range(2)]
    X = group.msm(witness, Gs[:2])
    Y = group.msm(witness, Gs[2:4])

    statement = GroupMorphismPreimage(group)
    [var_x, var_r] = statement.allocate_scalars(2)
    statement.append_equation(X, [(var_x, Gs[0]), (var_r, Gs[1])])
    statement.append_equation(Y, [(var_x, Gs[2]), (var_r, Gs[3])])

    # Test batched proof
    batched_proof = proof = prove_batchable(rng, b"test", statement, witness, group)
    print(f"Proof: {to_hex(batched_proof)}")
    assert verify_batchable(b"test", statement, batched_proof, group)


def main():
    discrete_logarithm()
    dleq()
    pedersen_commitment()
    pedersen_commitment_dleq()


if __name__ == "__main__":
    main()