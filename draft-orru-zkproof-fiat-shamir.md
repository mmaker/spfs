---
title: "Fiat-Shamir Heuristic"
category: info

docname: draft-orru-zkproof-fiat-shamir-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
# area: AREA
workgroup: Zkproof
keyword:
 - zero knowledge
 - hash
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "mmaker/stdsigma"
  latest: "https://mmaker.github.io/stdsigma/draft-orru-zkproof-fiat-shamir.html"

author:
-
    fullname: "Michele Orrù"
    organization: CNRS
    email: "m@orru.net"

normative:

informative:

--- abstract

This document describes the Fiat-Shamir transform via a stateful hash object that is capable of supporting a number of different hash functions, to "absorb" elements from different domains, and produce pseudoranom elements "squeezing" from the hash object.

--- middle

# Introduction

A stateful hash object (SHO) can absorb inputs incrementally and squeeze variable-length unpredictable messages.
On a high level, it consists of three main components:

- A label.
- An underlying hash function H, in a chosen mode, which the SHO invokes to execute the actions.

The core actions supported are:

- `Absorb` indicates a sequence of len elements in input
- `Squeeze` indicates an amount len of output to be produced

# The API

A stateful hash object has the following interface:

  class SHO:
      Unit

      def new(label: bytes) -> SHO
      def absorb(self, x)
      def squeeze(self, length: int) -> [Unit]
      def finalize(self)

were

- `SHO.init(label) -> sho`, creates a new `sho` object with a description label `label`;
- `sho.absorb(values)`, absorbs a list of native elements (that is, of type `Unit`);
- `sho.squeeze(length)`, squeezes from the `sho` object a list of `Unit` elements.
- `sho.finalize()`, deletes the hash object safely.

The above can be extended to support absorption and squeeze from different domains. Such extensions are called codecs.

# Hash registry

## Shake128 implementation

SHAKE128 is a variable-length hash function based on the Keccak sponge construction [SHA3]. It belongs to the SHA-3 family but offers a flexible output length, and provides 128 bits of security against collision attacks, regardless of the output length requested.


### Initialization

    new(self, label)

    Inputs:

    - label, a byte array

    Outputs:

    -  a stateful hash object interface

    1. h = shake_128(label)
    2. return h

### Absorb

    absorb(sho, x)

    Inputs:

    - sho, a hash state
    - x, a byte array

    1. h.update(x)

This method is also re-exported as `absorb_bytes`.

### Squeeze

    squeeze(sho, length)

    Inputs:

    - sho, a stateful hash object
    - length, the number of elements to be squeezed

    1. h.digest(length)

This method is also re-exported as `squeeze_bytes`.

# Codecs registry

## P-384 (secp384r1)

### Absorb scalars

    absorb_scalars(sho, scalars)

    Inputs:
### Absorb elements

### Squeeze scalars

[SHA3] FIPS PUB 202, "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions," August 2015. https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
