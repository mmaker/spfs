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

This document describes the Fiat-Shamir transform.

--- middle

# Stateful Hash Object API

A stateful hash objects can absorb inputs incrementally and squeeze variable-length unpredictable messages.

## The API

- `SHO.init(iv) -> sho`, creates a new `sho` object with a description;
- `sho.absorb(values)`, absorbs a list of "native" elements (that is, elements in the same domain of the hash function);
- `sho.squeeze(length)`, squeezes from the `sho` object a list of "native" elements
- `sho.finalize()`, deletes the hash object safely.


## Initialization vector for generic protocols

## Sigma protocols example

Two hash states are needed, one public and one private for nonce generation. They are built as follows.

    iv  = SHA3-256(label)
    challenge = SHAKE128(iv || commitment)
    private_nonce = SHAKE128(iv || random || pad || witness)
