from abc import ABC, abstractmethod

from collections import namedtuple
from sagelib.arc_groups import G, GenG, GenH, hash_to_group
from util import to_hex, to_bytes
from sagelib.sho import Shake128GroupP384


def prove_batchable(rng, label, statement, witness):
    sp = SchnorrProof(statement)
    (prover_state, commitment) = sp.prover_commit(rng, witness)
    challenge, = Shake128GroupP384(label).absorb_elements(commitment).squeeze_scalars(1)
    response = sp.prover_response(prover_state, challenge)

    assert sp.verifier(commitment, challenge, response)
    return (
        Group.serialize_elements(commitment) +
        Group.serialize_scalars(response)
    )


def prove_batchable_1(rng, sp, h, witness):
    (prover_state, commitment) = sp.prover_commit(rng, witness)
    challenge, = h.absorb_elements(commitment).squeeze_scalars(1)
    response = sp.prover_response(prover_state, challenge)

    assert sp.verifier(commitment, challenge, response)
    return (
        Group.serialize_elements(commitment) +
        Group.serialize_scalars(response)
    )

def verify_batchable(label, statement, proof):
    commitment_bytes = proof[: statement.commit_bytes_len]
    commitment = Group.deserialize_elements(commitment_bytes)

    response_bytes = proof[statement.commit_bytes_len :]
    response = Group.deserialize_scalars(response_bytes)

    challenge, = Shake128GroupP384(label).absorb_elements(commitment).squeeze_scalars(1)

    sp = SchnorrProof(statement)
    return sp.verifier(commitment, challenge, response)


# the combiner for arbitrary statements

class SigmaProtocol(ABC):
    @abstractmethod
    def __init__(self, statement):
        raise NotImplementedError

    @abstractmethod
    def prover_commit(self, rng, witness):
        raise NotImplementedError

    @abstractmethod
    def prover_response(self, prover_state, challenge):
        raise NotImplementedError

    @abstractmethod
    def verifier(self, commitment, challenge, response):
        raise NotImplementedError

    # optional
    def simulate_response(self):
        raise NotImplementedError

    # optional
    def simulate_commitment(self, response, challenge):
        raise NotImplementedError


Witness = list
ScalarVar = int

# A sparse linear combination
LinearCombination = namedtuple("LinearCombination", ["scalar_indices", "elements"])
ProverState = namedtuple("ProverState", ["witness", "nonces"])

class Morphism:
    def __init__(self):
        self.linear_combinations = []
        self.num_scalars = 0

    def append(self, linear_combination: LinearCombination):
        self.linear_combinations.append(linear_combination)

    @property
    def num_statements(self):
        return len(self.linear_combinations)

    # def map(self, scalars):
    def __call__(self, scalars: Witness):
        image = []
        for linear_combination in self.linear_combinations:
            coefficients = [scalars[i] for i in linear_combination.scalar_indices]
            image.append(Group.msm(coefficients, linear_combination.elements))
        return image

class GroupMorphismPreimage:
    def __init__(self):
        self.morphism = Morphism()
        self.image = []

    @property
    def commit_bytes_len(self):
        return self.morphism.num_statements * Group.element_byte_length()

    def append_equation(self, lhs, rhs):
        linear_combination = LinearCombination(
            scalar_indices=[x[0] for x in rhs],
            elements=[x[1] for x in rhs]
        )
        self.morphism.append(linear_combination)
        self.image.append(lhs)

    def allocate_scalars(self, n):
        indices = [ScalarVar(i)
                   for i in range(self.morphism.num_scalars, self.morphism.num_scalars + n)]
        self.morphism.num_scalars += n
        return indices


class SchnorrProof(SigmaProtocol):
    def __init__(self, statement):
        self.statement = statement

    def prover_commit(self, rng, witness):
        nonces = [Group.random_scalar(rng) for _ in range(self.statement.morphism.num_scalars)]
        prover_state = ProverState(witness, nonces)
        commitment = self.statement.morphism(nonces)
        return (prover_state, commitment)

    def prover_response(self, prover_state: ProverState, challenge):
        (witness, nonces) = prover_state
        return [
            (nonces[i] + challenge * witness[i]) % Group.order()
            for i in range(self.statement.morphism.num_scalars)
        ]

    def verifier(self, commitment, challenge, response):
        assert len(commitment) == self.statement.morphism.num_statements
        assert len(response) == self.statement.morphism.num_scalars

        expected = self.statement.morphism(response)
        got = [
            commitment[i] + statement.image[i] * challenge
            for i in range(self.statement.morphism.num_statements)
        ]

        # fail hard if the proof does not verify
        assert got == expected
        return True

    def serialize_batchable(self, commitment, challenge, response):
        return (
            Group.serialize_elements(commitment) +
            Group.serialize_scalars(response)
        )

    def deserialize_batchable(self, encoded):
        commitment_bytes = encoded[: self.statement.commit_bytes_len]
        commitment = Group.deserialize_elements(commitment_bytes)

        response_bytes = encoded[self.statement.commit_bytes_len :]
        response = Group.deserialize_scalars(response_bytes)

        return (commitment, response)




if __name__ == "__main__":
    from sagelib.arc_groups import GroupP384
    from sagelib.test_drng import TestDRNG

    Group = GroupP384()
    Gs = [hash_to_group(to_bytes("gen"), to_bytes(f"{i}")) for i in range(100)]

    ## Schnorr proof example
    ## proves that
    # X = x0 * G  + x1 * H
    # Y = x0 * G' + x1 * H'
    rng = TestDRNG("test vector seed".encode('utf-8'))

    witness = [Group.random_scalar(rng) for i in range(2)]
    X = Group.msm(witness, Gs[:2])
    Y = Group.msm(witness, Gs[2:4])

    statement = GroupMorphismPreimage()
    [var_x, var_r] = statement.allocate_scalars(2)
    statement.append_equation(X, [(var_x, Gs[0]), (var_r, Gs[1])])
    statement.append_equation(Y, [(var_x, Gs[2]), (var_r, Gs[3])])

    #print("Schnorr proof passed")
    proof = prove_batchable(rng, b"test", statement, witness)
    print(f"Proof: {to_hex(proof)}")
    assert verify_batchable(b"test", statement, proof)