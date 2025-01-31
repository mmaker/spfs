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

## Σ-protocols over prime-order groups

The following sub-section present concrete instantiations of Σ-protocols over prime-order groups such as ellitpic curves.

### Constraint representation

Traditionally, Σ-protocols are defined in Camenish-Stadtler notation as (for example):

    VRF = {
      (x),            // Secret variables
      (A, B, G, H),   // Public group elements
      A = x * B,      // Statements to prove
      G = x * H
    }

Internally, they can be represented as:

    struct SigmaConstraintSystem {
        // A label associated to the proof
        label: String
        // the list of statements to be proven
        statements: [Equation; num_statements]

        // the number of secret scalars
        num_scalars: usize
        // the number of equations to be proven
        num_statements: usize
        // the group elements to be used in the proof
        group_elts: Vec<Group>
    }

where `Equation` is the following type:

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

For those familiar with the matrix notation, `SigmaConstraintSystem` is encoding a sparse linear equation of the form `A * scalars = B`, where `A` is a matrix of `num_statements` rows, `scalars.len` columns, of group elements. Each element is identified by a pair `(usize, usize)` denoting the column index, and the value (an index referring to `generators`).
The vector `B` is a list of indices referring to `generators`.

This is equivalently done with a constraint system:

    cs = ConstraintSystem.new("VRF")
    [x] = cs.allocate_scalars(1)
    [A, B, G, H] = cs.allocate_group_elt(4)
    cs.append_equation(lhs=A, rhs=[(x, B)])
    cs.append_equation(lhs=G, rhs=[(x, H)])

In the above, `ConstraintSystem.new()` creates a new `ConstraintSystem` with label `"VRF"`.

    class ConstraintSystem:
        def new(label):
            return ConstraintSystem {
                label,
                num_statements: 0,
                num_scalars: 0,
                group_elts: [],
                statements: [],
            }

        def allocate_scalars(self, n: usize):
            indices = range(self.num_scalars, self.num_scalars + n)
            self.num_scalars += n
            return indices

        def allocate_group_elt(self, n: usize):
            indices = range(len(self.group_elts), len(self.group_elts)
            self.group_elts.extend([None; self.indices])
            return indices

        def assign_point(self, ptr: usize, value: Group):
            self.group_elts[ptr] = value

        def append_equation(self, lhs, rhs):
            equation = Equation {lhs, rhs}
            self.num_statements += 1
            self.statements.append(equation)

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

    class SchnorrProof:
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

        def verify(self, commitment, challenge, response):
            image = [equation.lhs for equation in self.cs.statements.equations]
            commitment = challenge * image + self.cs.map(response)

### Prover

We describe below the prover's wrapping function.

    def prove_short(statement, witness):
        sp = SchnorrProof.new(statement)
        (prover_state, commitment) = sp.prover_commmit(witness)
        challenge = sp.challenge(commitment)
        response = sp.prover_response(commitment, challenge)
        return scalar_to_bytes(challenge) + scalar_to_bytes(response)

    def prove_batchable(statement, witness):
        sp = SchnorrProof.new(statement)
        (prover_state, commitment) = sp.prover_commmit(witness)
        challenge = sp.challenge(commitment)
        response = sp.prover_response(commitment, challange)
        return point_to_bytes(commitment) + scalar_to_bytes(response)

### Verifier

    def verify_batchable(statement, proof):
        sp = SchnorrProof.new(statement)
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


# Acknowledgments
{:numbered ="false"}

Jan Bobolz, Stephan Krenn, Mary Maller, Ivan Visconti, Yuwen Zhang.
