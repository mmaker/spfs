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

A stateful hash objects can absorb inputs incrementally and squeeze variable-length unpredictable messages.
On a high level, it consists of three main components:

- A label.
- An underlying hash function H, in a chosen mode, which the SHO invokes to execute the actions.

The core actions supported are:

- `Absorb` indicates a sequence of len elements in input to the SHO
- `Squeeze` indicates an amount len of output to be produced by the SHO

For instance, a SHO defined by:

- A label “test”
- A hash function SHAKE256
will result in a stateful hash that, given in input 32 bytes of data, will output a 32 bytes hash.

More formally, a SHO is a tuple <label, H>.

## The API

- `SHO.init(label) -> sho`, creates a new `sho` object with a description;
- `sho.absorb(values)`, absorbs a list of "native" elements (that is, elements in the same domain of the hash function);
- `sho.squeeze(length)`, squeezes from the `sho` object a list of "native" elements
- `sho.finalize()`, deletes the hash object safely.

## Initialization vector for generic protocols

## Sigma protocols example

Two hash states are needed, one public and one private for nonce generation. They are built as follows.

    iv  = SHA3-256(label)
    challenge = SHAKE128(iv || commitment)
    private_nonce = SHAKE128(iv || random || pad || witness)
