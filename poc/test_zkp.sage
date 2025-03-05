#!/usr/bin/sage
# vim: syntax=python

from sagelib.arc_groups import GroupP384, hash_to_group
from sagelib.zkp import GroupMorphismPreimage, prove_batchable, verify_batchable
from sagelib.test_drng import TestDRNG
from util import to_hex, to_bytes
from sagelib.sho import Shake128GroupP384

def main(path="vectors"):
    group = GroupP384()
    Gs = [hash_to_group(to_bytes("gen"), to_bytes(f"{i}")) for i in range(100)]

    ## Schnorr proof example
    ## proves that
    # X = x0 * G  + x1 * H
    # Y = x0 * G' + x1 * H'
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
    print(f"Batched proof: {to_hex(batched_proof)}")
    assert verify_batchable(b"test", statement, batched_proof, group)

if __name__ == "__main__":
    main()