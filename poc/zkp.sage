from abc import ABC, abstractmethod

from collections import namedtuple
from sagelib.arc_groups import G, GenG, GenH, hash_to_group
from util import to_hex, to_bytes
from sagelib.sho import Shake128GroupP384

def prove_batchable(rng, label, statement, witness, group):
    sp = SchnorrProof(statement, group)
    (prover_state, commitment) = sp.prover_commit(rng, witness)
    challenge, = Shake128GroupP384(label).absorb_elements(commitment).squeeze_scalars(1)
    response = sp.prover_response(prover_state, challenge)

    assert sp.verifier(commitment, challenge, response)
    return (
        group.serialize_elements(commitment) +
        group.serialize_scalars(response)
    )


def prove_batchable_1(rng, sp, h, witness, group):
    (prover_state, commitment) = sp.prover_commit(rng, witness)
    challenge, = h.absorb_elements(commitment).squeeze_scalars(1)
    response = sp.prover_response(prover_state, challenge)

    assert sp.verifier(commitment, challenge, response)
    return (
        group.serialize_elements(commitment) +
        group.serialize_scalars(response)
    )

def verify_batchable(label, statement, proof, group):
    commitment_bytes = proof[: statement.commit_bytes_len]
    commitment = group.deserialize_elements(commitment_bytes)

    response_bytes = proof[statement.commit_bytes_len :]
    response = group.deserialize_scalars(response_bytes)

    challenge, = Shake128GroupP384(label).absorb_elements(commitment).squeeze_scalars(1)

    sp = SchnorrProof(statement, group)
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
    def __init__(self, group):
        self.linear_combinations = []
        self.num_scalars = 0
        self.group = group

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
            image.append(self.group.msm(coefficients, linear_combination.elements))
        return image

class GroupMorphismPreimage:
    def __init__(self, group):
        self.morphism = Morphism(group)
        self.image = []
        self.group = group

    @property
    def commit_bytes_len(self):
        return self.morphism.num_statements * self.group.element_byte_length()

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
    def __init__(self, statement, group):
        self.statement = statement
        self.group = group

    def prover_commit(self, rng, witness):
        nonces = [self.group.random_scalar(rng) for _ in range(self.statement.morphism.num_scalars)]
        prover_state = ProverState(witness, nonces)
        commitment = self.statement.morphism(nonces)
        return (prover_state, commitment)

    def prover_response(self, prover_state: ProverState, challenge):
        (witness, nonces) = prover_state
        return [
            (nonces[i] + challenge * witness[i]) % self.group.order()
            for i in range(self.statement.morphism.num_scalars)
        ]

    def verifier(self, commitment, challenge, response):
        assert len(commitment) == self.statement.morphism.num_statements
        assert len(response) == self.statement.morphism.num_scalars

        expected = self.statement.morphism(response)
        got = [
            commitment[i] + self.statement.image[i] * challenge
            for i in range(self.statement.morphism.num_statements)
        ]

        # fail hard if the proof does not verify
        assert got == expected
        return True

    def serialize_batchable(self, commitment, challenge, response):
        return (
            self.group.serialize_elements(commitment) +
            self.group.serialize_scalars(response)
        )

    def deserialize_batchable(self, encoded):
        commitment_bytes = encoded[: self.statement.commit_bytes_len]
        commitment = self.group.deserialize_elements(commitment_bytes)

        response_bytes = encoded[self.statement.commit_bytes_len :]
        response = self.group.deserialize_scalars(response_bytes)

        return (commitment, response)
