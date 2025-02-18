---
title: "Sigma Protocols"
category: info

docname: draft-orru-zkproof-sigma-latest
submissiontype: independent
number:
date:
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - zero-knowledge
venue:
#  group: WG
#  type: Working Group
#  mail: WG@examplecom
#  arch: https://examplecom/WG
  github: "mmaker/stdsigma"
  latest: "https://mmaker.github.io/stdsigma/draft-orru-zkproof-sigma.html"

author:
 -
    fullname: "Michele Orrù"
    organization: CNRS
    email: "m@orru.net"

normative:

informative:

--- abstract

This document describes Sigma protocols, a secure, general-purpose non-interactive zero-knowledge proof of knowledge. Concretely, the scheme allows proving knowledge of a witness, without revealing any information about the undisclosed messages or the signature itself, while at the same time, guarantying soundness of the overall protocols.

--- middle

# Σ-protocols

A Sigma Protocol is a simple zero-knowledge proof of knowledge. Any sigma protocols consists of three objects:

- a commitment, sometimes also called nonce. This message is computed by the prover.
- a challenge, computed using the Fiat-Shamir transformation using a hash function.
- a response, computed by the prover, which depends on the commitment and the challenge.

A sigma protocol allows to convince a **verifier** of the knowledge of a secret **witness** satisfying an **instance** of the `ConstraintSystem`.

## Generic interface

Any sigma protocol consists of the following methods:

    class SigmaProtocol:
       def new(il: bytes, instance: ConstraintSystem) -> SigmaProtocol
       def prover_commit(self, witness: Witness) -> (commitment, prover_state)
       def prover_response(self, prover_state, challenge) -> response
       def verifier(self, commitment, challenge, response) -> bool
       # optional
       def simulate_response() -> response
       # optional
       def simulate_commitment(response, challenge) -> commitment

In the above:
Here's the list of functions in markdown:

- `new(il: [u8], cs: ConstraintSystem) -> SigmaProtocol`, denoting the initialization function. This function takes as input a label identifying local context information (such as: session identifiers, to avoid replay attacks; protocol metadata, to avoid hijacking; optionally, a timestamp and some pre-shared randomness, to guarantee freshness of the proof) and an instance generated via the `ConstraintSystem`, the public information shared between prover and verifier.
This function should pre-compute parts of the statement, or initialize the state of the hash function.

- `prover_commit(self, witness: Witness) -> (commitment, prover_state)`, denoting the **commitment phase**, that is, the computation of the first message sent by the prover in a Sigma protocol. This method outputs a new commitment together with its associated prover state, depending on the witness known to the prover and the statement to be proven. This step generally requires access to a high-quality entropy source. Leakage of even just of a few bits of the nonce could allow for the complete recovery of the witness. The commitment meant to be shared, while `prover_state` must be kept secret.

- `prover_response(self, prover_state, challenge) -> response`, denoting the **response phase**, that is, the computation of the second message sent by the prover, depending on the witness, the statement, the challenge received from the verifier, and the internal state `prover_state`. The returned value `response` is meant to be shared.

- `verifier(self, commitment, challenge, response) -> bool`, denoting the **verifier algorithm**. This method checks that the protocol transcript is valid for the given statement. The verifier algorithm outputs nothing if verification succeeds, or an error if verification fails.

The final two algorithms describe the **zero-knowledge simulator** and are optional. The simulator is primarily an efficient algorithm for proving zero-knowledge in a theoretical construction, but it is also needed for verifying short proofs and for or-composition, where a witness is not known and thus has to be simulated. We have:

- `simulate_response() -> response`, denoting the first stage of the simulator. It is an algorithm drawing a random response that follows the same output distribution of the algorithm  `prover_response`

- `simulate_commitment(response, challenge) -> commitment`, returning a simulated commitment -- the second phase of the zero-knowledge simulator.

## Σ-protocols over prime-order groups

The following sub-section present concrete instantiations of Σ-protocols over prime-order groups such as ellitpic curves.

### Group abstraction

Because of their dominance, the presentation in the following focuses on proof goals over elliptic curves, therefore leveraging additive notation. For prime-order
subgroups of residue classes, all notation needs to be changed to multiplicative, and references to elliptic curves (e.g., curve) need to be replaced by their respective
counterparts over residue classes.
We therefore assume two objects are available to the programmer:

    Group: Zero + Add<Group> + Sub<Group> + Mul<Scalar> + From<int> + Eq<Group>
    Scalar: Zero + One + Div<Scalar> + Add<Scalar> + Sub<Scalar> + From<int> + Eq<Group>

### Constraint representation

Traditionally, Σ-protocols are defined in Camenish-Stadtler notation as (for example):

    VRF(A, B, G, H) = PoK{
      (x):        // Secret variables
      A = x * B,  // Statements to prove
      G = x * H
    }

Internally, they can be represented as:

    struct ConstraintSystem {
        // A label associated to the proof
        label: String
        // the list of statements to be proven
        statements: Combiner[Statement; num_statements]

        // the number of secret scalars
        num_scalars: usize
        // the number of equations to be proven
        num_statements: usize
        // the group elements to be used in the proof
        group_elts: Vec<Group>
    }

A statement `Statement` defines different types of predicates that can be proven by the zero-knowledge proof
For now, consider:

    enum Statement {
       Eq(Equation),
    }

The abstraction `Statement` allows to implement different types of statements and combiners of those, such as OR statements, validity of t-out-of-n statements, and more.

#### Equations

The object `Equation` encodes linear relation:

    struct Equation {
        // An index in the list of generators representing the left-hand side part of the equation
        lhs: usize
        // A list of (ScalarIndex, GroupEltIndex) referring to a scalar and a generator
        rhs: Vec<(usize, usize)>
    }


A witness is defined as:

    struct Witness {
        scalars: [Scalar; num_scalars] // The set of secret scalars
    }

For those familiar with the matrix notation, `ConstraintSystem` is encoding a sparse linear equation of the form `A * scalars = B`, where `A` is a matrix of `num_statements` rows, `scalars.len` columns, of group elements. Each element is identified by a pair `(usize, usize)` denoting the column index, and the value (an index referring to `generators`).
The vector `B` is a list of indices referring to `generators`.

This is equivalently done with a constraint system:

    cs = ConstraintSystem.new("VRF")
    [x] = cs.allocate_scalars(1)
    [A, B, G, H] = cs.allocate_group_elt(4)
    cs.append_equation(lhs=A, rhs=[(x, B)])
    cs.append_equation(lhs=G, rhs=[(x, H)])

In the above, `ConstraintSystem.new()` creates a new `ConstraintSystem` with label `"VRF"`.

#### ConstraintSystem instantiation

    new(label)

    Inputs:

    - labels, a byte array

    Outputs:

    - a ConstraintSystem instance

    Procedure:

    1.  return ConstraintSystem {
    2.        label,
    3.        num_statements: 0,
    4.        num_scalars: 0,
    5.        group_elts: [],
    6.        statements: [],
    7.    }

#### Scalar witness allocation

    allocate_scalars(self, n)

    Inputs:
        - self, the current state of the ConstraintSystem
        - n, the number of scalars to allocate
    Outputs:
        - indices, a list of integers each pointing to the new allocated scalars

    Procedure:

    1. indices = range(self.num_scalars, self.num_scalars + n)
    2. self.num_scalars += n
    3. return indices

#### Public group element allocation

    allocate_group_elt(self, n)

    Inputs:

       - self, the current state of the constraint system
       - n, the number of group elements to allocate

    Outputs:

       - indices, a list of integers each pointing to the new allocated group elements.

    Procedure:

    1. indices = range(len(self.group_elts), len(self.group_elts) + n)
    2. self.group_elts.extend([None] * n)
    3. return indices

#### Group element assignment

    assign_point(self, ptr, value)

    Inputs:

        - self, the current state of the constraint system
        - ptr, the pointer to the group element to be assigned
        - value, the value to be assigned to the group element

    Procedure:

    1. self.group_elts[ptr] = value

#### Enforcing an equation

This function adds an equation statement constraint to the instance, expressed as a left-hand side (the target group element), and a list of pairs encoding a linear combination of scalars and group elements.

    append_equation(self, lhs, rhs)

    Inputs:

    - self, the current state of the constraint system
    - lhs, the left-hand side of the equation (an index in the list of generators)
    - rhs, the right-hand side of the equation (a list of (ScalarIndex, GroupEltIndex) pairs)

    Outputs:

    - An Equation instance that enforces the desired relation

    Procedure:

    1. equation = Equation {lhs, rhs}
    2. self.num_statements += 1
    3. self.statements.append(equation)

A witness can be mapped to a group element via:

    class Witness:
        def map(cs):
            assert cs.num_scalars = self.scalars.len()
            image = [0; Group]
            for i in range(cs.num_statements):
                eq_scalars = [self.scalars[idx_pair[0]] for idx_pair in cs.equations[i].rhs]
                eq_group_elt = [cs.group_elts[idx_pair[1]] for idx_pair in cs.equations[i].rhs]
                image[i] = multi_scalar_multiplication(eq_scalars, eq_group_elt)
            return image

## Core protocol

    class SigmaProtocol:
        def new(cs: ConstraintSystem):
            self.iv = generate_statement_iv(statement)
            self.cs = cs

        def prover_commit(self, witness: Witness):
            nonces = SHO.init(iv).random_seed().divide().absorb_scalars(witness).squeeze_scalars(self.cs.num_scalars)
            prover_state = (witness, nonces)
            commitment = self.cs.map(witness)
            return (prover_state, commitment)

        def prover_response(self, prover_state, challenge):
            response = [0; self.cs.num_scalars]
            for i in range(self.cs.num_scalars):
                response[i] = witness[i] + challenge * nonces[i]
            return response

        def challenge(self, commitment):
            SHO.init(iv).absorb_group_elt(commitment).squeeze_scalar(1)


#### Verifier procedure

    verify(self, commitment, challenge, response)

    Inputs:

    - self, the current state of the SigmaProtocol
    - commitment, the commitment generated by the prover
    - challenge, the challenge generated by the verifier
    - response, the response generated by the prover

    Outputs:

    - A boolean indicating whether the verification succeeded

    Procedure:

    1. image = [equation.lhs for equation in self.cs.statements.equations]
    2. expected_commitment = challenge * image + self.cs.map(response)
    3. return expected_commitment == commitment

### Prover

We describe below the prover's wrapping function.

    def prove_short(statement, witness):
        sp = SigmaProtocol.new(statement)
        (prover_state, commitment) = sp.prover_commmit(witness)
        challenge = sp.challenge(commitment)
        response = sp.prover_response(commitment, challenge)
        return scalar_to_bytes(challenge) + scalar_to_bytes(response)

    def prove_batchable(statement, witness):
        sp = SigmaProtocol.new(statement)
        (prover_state, commitment) = sp.prover_commmit(witness)
        challenge = sp.challenge(commitment)
        response = sp.prover_response(commitment, challange)
        return point_to_bytes(commitment) + scalar_to_bytes(response)

### Verifier

    def verify_batchable(statement, proof):
        sp = SigmaProtocol.new(statement)
        commitment = read_group_elements(proof)

## Nonce and challenge derivation

Two types of randomness are needed for a sigma protocol:

1. A nonce seeding the randomness used to produce the commitment of the first round of the protocol
2. A challenge representing the verifier's public random coin.

The challenge of a Schnorr proof is derived with

    challenge = sho.init(iv).absorb_group_elt(commitment).squeeze_scalar(1)

This can be generated with:

    nonce = sho.init(iv)
               .absorb_bytes(random)
               .ratchet()
               .absorb_scalars(witness)
               .squeeze_scalars(cs.num_scalars)

The `iv`, which must properly separate the application and the statement being proved, is described below.

### Statement generation

Let `H` be a hash object. The statement is encoded in a stateful hash object as follows.

    hasher = H.new(domain_separator)
    hasher.update_usize([cs.num_statements, cs.num_scalars])
    for equation in cs.equations:
      hasher.update_usize([equation.lhs, equation.rhs[0], equation.rhs[1]])
    hasher.update(generators)
    iv = hasher.digest()

In simpler terms, without stateful hash objects, this should correspond to the following:

    bin_challenge = SHAKE128(iv).update(commitment).digest(scalar_bytes)
    challenge = int(bin_challenge) % p

and the nonce is produced as:

    bin_nonce = SHAKE128(iv)
                .update(random)
                .update(pad)
                .update(cs.scalars)
                .digest(cs.num_scalars * scalar_bytes)
    nonces = [int(bin_nonce[i*scalar_bytes: i*(scalar_bytes+1)]) % p
              for i in range(cs.num_scalars-1)]

Where:
    - `pad` is a (padding) zero string of length `168 - len(random)`.
    - `scalar_bytes` is the number of bytes required to produce a uniformly random group element
    - `random` is a random seed obtained from the operating system memory

## Proof generation

## Acknowledgments
{:numbered ="false"}

Jan Bobolz, Stephan Krenn, Mary Maller, Ivan Visconti, Yuwen Zhang.
