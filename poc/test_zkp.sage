#!/usr/bin/sage
# vim: syntax=python

try:
    from sagelib.zkp_groups import G as group, Gs as generators, hash_to_group, context_string
    from sagelib.zkp import GroupMorphismPreimage, prove, verify
    from sagelib.test_drng import TestDRNG
    from util import to_hex, to_bytes
    from sagelib.sho import Shake128GroupP384
    import json
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def wrap_write(fh, arg, *args):
    line_length = 68
    string = " ".join( [arg] + list(args))
    for hunk in (string[0+i:line_length+i] for i in range(0, len(string), line_length)):
        if hunk and len(hunk.strip()) > 0:
            fh.write(hunk + "\n")

def write_blob(fh, name, blob):
    wrap_write(fh, name + ' = ' + to_hex(blob))

def write_value(fh, name, value):
    wrap_write(fh, name + ' = ' + value)

def write_group_vectors(fh, label, vector):
    fh.write("## " + label + "\n")
    fh.write("~~~\n")
    for key in vector:
        write_value(fh, key, vector[key])
    fh.write("~~~\n\n")

def discrete_logarithm(vectors):
    """
    Proves the following statement:

        DL(X) = PoK{(x): X = x * G}

    """
    rng = TestDRNG("test vector seed".encode('utf-8'))
    G = group.generator()
    x = group.random_scalar(rng)
    X = G * x

    statement = GroupMorphismPreimage(group)
    [var_x] = statement.allocate_scalars(1)
    statement.append_equation(X, [(var_x, G)])

    proof = prove(rng, b"test", statement, [x], group)
    hex_proof = to_hex(proof)
    print(f"discrete_logarithm proof: {hex_proof}\n")
    assert verify(b"test", statement, proof, group)

    vectors["discrete_logarithm"] = {
        "Context": context_string,
        "Statement": "TODO",
        "Proof": hex_proof,
    }

def dleq(vectors):
    """
    Proves the following statement:

        DLEQ(G, H, X, Y) = PoK{(x): X = x * G, Y = x * H}

    """
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

    proof = prove(rng, b"test", statement, [x], group)
    hex_proof = to_hex(proof)
    print(f"dleq proof: {hex_proof}\n")
    assert verify(b"test", statement, proof, group)

    vectors["dleq"] = {
        "Context": context_string,
        "Statement": "TODO",
        "Proof": hex_proof,
    }

def pedersen_commitment(vectors):
    """
    Proves the following statement:

        PEDERSEN(G, H, C) = PoK{(x, r): C = x * G + r * H}
    """
    rng = TestDRNG("test vector seed".encode('utf-8'))
    G = group.generator()
    H = group.random(rng)
    x = group.random_scalar(rng)
    r = group.random_scalar(rng)

    C = G * x + H * r
    statement = GroupMorphismPreimage(group)
    var_x, var_r = statement.allocate_scalars(2)
    statement.append_equation(C, [(var_x, G), (var_r, H)])

    proof = prove(rng, b"test", statement, [x, r], group)
    hex_proof = to_hex(proof)
    print(f"pedersen_commitment proof: {hex_proof}\n")
    assert verify(b"test", statement, proof, group)

    vectors["pedersen_commitment"] = {
        "Context": context_string,
        "Statement": "TODO",
        "Proof": hex_proof,
    }

def pedersen_commitment_dleq(vectors):
    """
    Proves the following statement:

        PEDERSEN(G0, G1, G2, G3, X, Y) = PoK{(x0, x1):  X = x0 * G0  + x1 * G1, Y = x0 * G2 + x1 * G3}
    """
    Gs = [hash_to_group(to_bytes("gen"), to_bytes(f"{i}")) for i in range(100)]

    rng = TestDRNG("test vector seed".encode('utf-8'))

    witness = [group.random_scalar(rng) for i in range(2)]
    X = group.msm(witness, generators[:2])
    Y = group.msm(witness, generators[2:4])

    statement = GroupMorphismPreimage(group)
    [var_x, var_r] = statement.allocate_scalars(2)
    statement.append_equation(X, [(var_x, Gs[0]), (var_r, Gs[1])])
    statement.append_equation(Y, [(var_x, Gs[2]), (var_r, Gs[3])])

    # Test batched proof
    proof = prove(rng, b"test", statement, witness, group)
    hex_proof = to_hex(proof)
    print(f"pedersen_commitment_dleq proof: {hex_proof}\n")
    assert verify(b"test", statement, proof, group)

    vectors["pedersen_commitment_dleq"] = {
        "Context": context_string,
        "Statement": "TODO",
        "Proof": hex_proof,
    }

def main(path="vectors"):
    vectors = {}
    discrete_logarithm(vectors)
    dleq(vectors)
    pedersen_commitment(vectors)
    pedersen_commitment_dleq(vectors)

    with open(path + "/allVectors.json", 'wt') as f:
        json.dump(vectors, f, sort_keys=True, indent=2)

    with open(path + "/allVectors.txt", 'wt') as f:
        for proof_type in vectors:
            write_group_vectors(f, proof_type, vectors[proof_type])

if __name__ == "__main__":
    main()