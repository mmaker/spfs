---
title: "Sigma Protocols"
category: info

docname: draft-orru-zkproof-sigma-protocols-latest
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
  latest: "https://mmaker.github.io/stdsigma/draft-orru-zkproof-sigma-protocols.html"

author:
 -
    fullname: "Michele Orrù"
    organization: CNRS
    email: "m@orru.net"

normative:

informative:
  NISTCurves: DOI.10.6028/NIST.FIPS.186-4
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    target: https://www.secg.org/sec1-v2.pdf
    date: false
    author:
      -
        ins: Standards for Efficient Cryptography Group (SECG)

--- abstract

This document describes Sigma protocols, a secure, general-purpose non-interactive zero-knowledge proof of knowledge. Concretely, the scheme allows proving knowledge of a witness, without revealing any information about the undisclosed messages or the signature itself, while at the same time, guarantying soundness of the overall protocols.

--- middle

# Introduction

A Sigma Protocol is a simple zero-knowledge proof of knowledge.
Any sigma protocols must define three objects:

- A commitment, sometimes also called nonce. This message is computed by the prover.
- A challenge, computed using the Fiat-Shamir transformation using a hash function.
- A response, computed by the prover, which depends on the commitment and the challenge.

A sigma protocol allows to convince a **verifier** of the knowledge of a secret **witness** satisfying a **statement**.

# Public functions

A sigma protocol provides the following two public functions.
For how to implement these function in prime-order groups and elliptic curves, see {{group-prove}} and {{group-verify}}.

## Proving function

    prove(domain_separator, statement, witness, rng)

    Inputs:
0=
    - domain_separator, a unique 32-bytes array uniquely indicating the protocol and the session being proven
    - statement, the instance being proven
    - witness, the witness for the given statement
    - rng, a random number generator

    Outputs:

    - proof, a byte array.

## Verification

    verify(domain_separator, statement, proof)

    Inputs:

    - domain_separator, a unique 32-bytes array uniquely indicating the protocol and the session being proven
    - statement, the instance being proven
    - proof, a byte array containing the cryptographic proof


    Outputs:

    - the verification bit

## Core interface

The public functions are obtained relying on an internal structure containing the definition of a sigma protocol.

    class SigmaProtocol:
       def new(instance: Statement) -> SigmaProtocol
       def prover_commit(self, witness: Witness) -> (commitment, prover_state)
       def prover_response(self, prover_state, challenge) -> response
       def verifier(self, commitment, challenge, response) -> bool
       # optional
       def simulate_response() -> response
       # optional
       def simulate_commitment(response, challenge) -> commitment

Where:

- `new(il: [u8], cs: ConstraintSystem) -> SigmaProtocol`, denoting the initialization function. This function takes as input a label identifying local context information (such as: session identifiers, to avoid replay attacks; protocol metadata, to avoid hijacking; optionally, a timestamp and some pre-shared randomness, to guarantee freshness of the proof) and an instance generated via the `ConstraintSystem`, the public information shared between prover and verifier.
This function should pre-compute parts of the statement, or initialize the state of the hash function.

- `prover_commit(self, witness: Witness) -> (commitment, prover_state)`, denoting the **commitment phase**, that is, the computation of the first message sent by the prover in a Sigma protocol. This method outputs a new commitment together with its associated prover state, depending on the witness known to the prover and the statement to be proven. This step generally requires access to a high-quality entropy source. Leakage of even just of a few bits of the nonce could allow for the complete recovery of the witness. The commitment meant to be shared, while `prover_state` must be kept secret.

- `prover_response(self, prover_state, challenge) -> response`, denoting the **response phase**, that is, the computation of the second message sent by the prover, depending on the witness, the statement, the challenge received from the verifier, and the internal state `prover_state`. The returned value `response` is meant to be shared.

- `verifier(self, commitment, challenge, response) -> bool`, denoting the **verifier algorithm**. This method checks that the protocol transcript is valid for the given statement. The verifier algorithm outputs nothing if verification succeeds, or an error if verification fails.

The final two algorithms describe the **zero-knowledge simulator** and are optional. The simulator is primarily an efficient algorithm for proving zero-knowledge in a theoretical construction, but it is also needed for verifying short proofs and for or-composition, where a witness is not known and thus has to be simulated. We have:

- `simulate_response() -> response`, denoting the first stage of the simulator. It is an algorithm drawing a random response that follows the same output distribution of the algorithm  `prover_response`

- `simulate_commitment(response, challenge) -> commitment`, returning a simulated commitment -- the second phase of the zero-knowledge simulator.

The abstraction `SigmaProtocol` allows implementing different types of statements and combiners of those, such as OR statements, validity of t-out-of-n statements, and more.

# Sigma protocols over prime-order groups

The following sub-section present concrete instantiations of sigma protocols over prime-order groups such as elliptic curves.
Traditionally, sigma protocols are defined in Camenish-Stadtler notation as (for example):

    DLEQ(G, H, X, Y) = PoK{
      (x):        // Secret variables
      X = x * G,  // Statements to prove
      Y = x * H
    }

stating that the proof name is "DLEQ", the public information (the **instance**) consists of the group elements `(G, X, H, Y)` denoted in upper-case, the private information (the **witness**) consists of the scalar `x`, and that the constraints (the equations) that need to be proven are
`x * G  = X` and `x * H = Y`.

## Schnorr proofs

### Public proving function {#group-prove}

The proving function demands to instantiate a statement and a witness (as in {{witness}})

    def prove(domain_separator, statement, witness, rng):

    Inputs:

    - domain_separator, a 32-bytes array that uniquely describes the protocol
    - statement, the instance being proven
    - witness, the secret prover's witness.

    Parameters:

    - SHO: A hash object implementing `absorb_elements` and `squeeze_scalars`

    1. sp = SchnorrProof(statement, group)
    2. (prover_state, commitment) = sp.prover_commit(rng, witness)
    3. challenge, = SHO(label).absorb_elements(commitment).squeeze_scalars(1)
    4. response = sp.prover_response(prover_state, challenge)
    5. assert sp.verifier(commitment, challenge, response)    # optional
    6. return (group.serialize_elements(commitment) + group.serialize_scalars(response))


Line 5 is optional, but implementations wanting to perform input validation for the witness SHOULD adopt it.

### Public verification function {#group-verify}

    verify(domain_separator, statement, proof)

    Inputs:

    - domain_separator, a unique 32-bytes array uniquely indicating the protocol and the session being proven
    - statement, the instance being proven
    - proof, a byte array containing the cryptographic proof

## Group abstraction

Because of their dominance, the presentation in the following focuses on proof goals over elliptic curves, therefore leveraging additive notation. For prime-order
subgroups of residue classes, all notation needs to be changed to multiplicative, and references to elliptic curves (e.g., curve) need to be replaced by their respective
counterparts over residue classes.

We detail the functions that can be invoked on these objects. Example choices can be found in {{ciphersuites}}.

### Group

- `identity()`, returns the neutral element in the group.
- `generator()`, returns the generator of the prime-order elliptic-curve subgroup used for cryptographic operations.
- `order()`: Outputs the order of the group `p`.
- `random()`: outputs a random element in the group.
- `serialize(elements: [Group; N])`: serializes a list of group elements and returns a canonical byte array `buf` of fixed length `Ng * N`.
- `deserialize(buffer)`: attempts to map a byte array `buffer` of size `Ng * N` into `[Group; N]`, and fails if the input is not the valid canonical byte representation of an element of the group. This function can raise a DeserializeError if deserialization fails.
- `add(element: Group)`: implements elliptic curve addition for the two group elements.
- `equal(element: Group)`, returns `true` if the two elements are the same and false` otherwise.
- `scalar_mul(scalar: Scalar)`, implements scalar multiplication for a group element by a scalar.

Functions such as `add`, `equal`, and `scalar_mul` SHOULD be implemented using operator overloading whenever possible.

### Scalar

- `identity()`: outputs the (additive) identity element in the scalar field.
- `add(scalar: Scalar)`: implements field addition for the elements in the field
- `mult(scalar: Scalar)`, implements field multiplication
- `random()`: outputs a random element
- `serialize(scalars: [Scalar; N])`: serializes a list of scalars and returns their canonical representation of fixed length `Ns * N`.

Functions such as `add`, `equal`, and `scalar_mul` SHOULD be implemented using operator overloading whenever possible.

## Witness representation {#witness}

A witness is simply a list of `num_scalars` elements.

    struct Witness {
        scalars: [Scalar; num_scalars] // The set of secret scalars
    }

### Constraint representation

Internally, the constraint can be represented as:

    struct Equations {
        // the list of statements to be proven
        matrix: [LinearCombination<ScalarIndex, &Group>; num_statements]
        // An list of references to group elements representing the left-hand side part of the equations
        image: [&Group; num_statements]

        // the number of secret scalars
        num_scalars: usize
        // the number of equations to be proven
        num_statements: usize
    }

The object `LinearCombination` encodes pairs of indices of the witness vector with group elements.
The initial example of the VRF can therefore be expressed with the following constraints:

    cs = Equations()
    [x] = cs.allocate_scalars(1)
    [A, B, G, H] = cs.allocate_group_elt(4)
    cs.append_equation(lhs=A, rhs=[(x, B)])
    cs.append_equation(lhs=G, rhs=[(x, H)])

In the above, `Equations.new()` creates a new `Equations` with label `"VRF"`.

#### Instantiation of the constraints

    new(label)

    Inputs:

    - label, a byte array

    Outputs:

    - a ConstraintSystem instance

    Procedure:

    1.  return Equations {
    2.        label,
    3.        num_statements: 0,
    4.        num_scalars: 0,
    5.        group_elements: [],
    6.        matrix: [],
    7.        image: []
    8.    }

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

    1. indices = range(len(self.group_elts), len(self.group_elements) + n)
    2. self.group_elements.extend([None] * n)
    3. return indices

#### Group element assignment

    assign_point(self, ptr, value)

    Inputs:

        - self, the current state of the constraint system
        - ptr, the pointer to the group element to be assigned
        - value, the value to be assigned to the group element

    Procedure:

    1. self.group_elements[ptr] = value

#### Enforcing an equation

This function adds an equation statement constraint to the instance, expressed as a left-hand side (the target group element), and a list of pairs encoding a linear combination of scalars and group elements.

    append_equation(self, lhs, rhs)

    Inputs:

    - self, the current state of the constraint system
    - lhs, the left-hand side of the equation
    - rhs, the right-hand side of the equation (a list of (ScalarIndex, GroupEltIndex) pairs)

    Outputs:

    - An Equation instance that enforces the desired relation

    Procedure:

    1. self.num_statements += 1
    2. self.image.append(lhs)
    3. self.matrix.append(rhs)

A witness can be mapped to a group element via:

    def map(self, witness: [Scalar; num_scalars]):
      assert self.num_scalars = witness.len()
      image = [0; Group]
      for i in range(self.num_statements):
          eq_scalars = [self.scalars[idx_pair[0]]
                        for idx_pair in self.matrix[i]]
          eq_group_elt = [self.group_elements[idx_pair[1]] for idx_pair in self.matrix[i]]
          image[i] = multi_scalar_multiplication(eq_scalars, eq_group_elt)
      return image

## Core protocol

    class SigmaProtocol:
        def new(statement: Statement):
            self.statement = statement

        def prover_commit(self, witness: Witness):
            nonces = Scalar::random()
            prover_state = (witness, nonces)
            commitment = self.statement.map(witness)
            return (prover_state, commitment)

        def prover_response(self, prover_state, challenge):
            response = [0; self.cs.num_scalars]
            for i in range(self.cs.num_scalars):
                response[i] = witness[i] + challenge * nonces[i]
            return response

### Verifier procedure

    verify(self, commitment, challenge, response)

    Inputs:

    - self, the current state of the SigmaProtocol
    - commitment, the commitment generated by the prover
    - challenge, the challenge generated by the verifier
    - response, the response generated by the prover

    Outputs:

    - A boolean indicating whether the verification succeeded

    Procedure:

    1. image = [equation.lhs for equation in self.statement.equations]
    2. expected_commitment = challenge * image + self.statement.map(response)
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

# Ciphersuites

## P-384

This ciphersuite uses P-384 {{NISTCurves}} for the Group.

### Elliptic curve group of P-384 (secp384r1) {{NISTCurves}}

- `order()`: Return 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973.
- `serialize([A])`: Implemented using the compressed Elliptic-Curve-Point-to-Octet-String method according to {{SEC1}}; `Ng = 49`.
- `deserialize(buf)`: Implemented by attempting to read `buf` into chunks of 49-byte arrays and convert them using the compressed Octet-String-to-Elliptic-Curve-Point method according to {{SEC1}}, and then performs partial public-key validation as defined in section 5.6.2.3.4 of {{!KEYAGREEMENT=DOI.10.6028/NIST.SP.800-56Ar3}}. This includes checking that the coordinates of the resulting point are in the correct range, that the point is on the curve, and that the point is not the point at infinity.

### Scalar Field of P-384 (secp384r1)

- `serialize(s)`: Relies on the Field-Element-to-Octet-String conversion according to {{SEC1}}; `Ns = 48`.
- `deserialize(buf)`: Reads the byte array `buf` in chunks of 48 bytes using Octet-String-to-Field-Element from {{SEC1}}. This function can fail if the input does not represent a Scalar in the range [0, G.Order() - 1].


# Acknowledgments
{:numbered ="false"}

The authors thank Jan Bobolz, Stephan Krenn, Mary Maller, Ivan Visconti, Yuwen Zhang for reviewing a previous edition of this specification.
