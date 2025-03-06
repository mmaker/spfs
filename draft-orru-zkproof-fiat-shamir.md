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
  group: "Crypto Forum"
  type: ""
  mail: "cfrg@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cfrg"
  github: "mmaker/stdsigma"
  latest: "https://mmaker.github.io/stdsigma/draft-orru-zkproof-fiat-shamir.html"

author:
-
    fullname: "Michele Orrù"
    organization: CNRS
    email: "m@orru.net"

normative:

informative:
  SHA3:
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

--- abstract

This document describes the Fiat-Shamir transform via a stateful hash object that is capable of supporting a number of different hash functions, to "absorb" elements from different domains, and produce pseudoranom elements "squeezing" from the hash object.

--- middle

# Introduction

A stateful hash object (SHO) can absorb inputs incrementally and squeeze variable-length unpredictable messages.
On a high level, it consists of three main components:

- A label.
- An underlying hash function H, in a chosen mode, which the SHO invokes to execute the actions.

The core actions supported are:

- `absorb` indicates a sequence of `len` elements in input
- `squeeze` indicates an amount `len` of output to be produced

# The API

A stateful hash object has the following interface:

  class SHO:
      type Unit

      def new(label: bytes) -> SHO
      def absorb(self, x)
      def squeeze(self, length: int) -> [Unit]
      def finalize(self)

where

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

    - sho, a stateful hash object
    - scalars, a list of elements of P-384's scalar field

    Constants:

    - scalar_byte_length = ceil(384/8)

    1. for scalar in scalars:
    2.     sho.absorb_bytes(scalar_to_bytes(scalar))

Where the function `scalar_to_bytes` is defined in {#notation}

### Absorb elements

    absorb_elements(sho, elements)

    Inputs:

    - sho, a stateful hash objects
    - elements, a list of P-384 group elements

    1. for element in elements:
    2.     sho.absorb_bytes(ecpoint_to_bytes(element))

### Squeeze scalars

    squeeze_scalars(sho, length)

    Inputs:

    - sho, a stateful hash object
    - length, an unsiged integer of 64 bits determining the output length.

    1. for i in range(length):
    2.     scalar_bytes = sho.squeeze_bytes(field_bytes_length + 16)
    3.     scalars.append(bytes_to_scalar_mod_order(scalar_bytes))

# Notation and Terminology {#notation}

For an elliptic curve, we consider two fields, the coordinate fields, which indicates the field over which the elliptic curve equation is defined, and the scalar field, over which the scalar operations are performed.

The following functions and notation are used throughout the document.

- `concat(x0, ..., xN)`: Concatenation of byte strings.
- `bytes_to_int` and `scalar_to_bytes`: Convert a byte string to and from a non-negative integer.
  `bytes_to_int` and `scalar_to_bytes` are implemented as `OS2IP` and `I2OSP` as described in
  {{!RFC8017}}, respectively. Note that these functions operate on byte strings
  in big-endian byte order. These functions MUST raise an exception if the integer over which they
  We consider the function `bytes_to_in`
- The function `ecpoint_to_bytes` converts an elliptic curve point in affine-form into an array string of length `ceil(ceil(log2(coordinate_field_order))/ 8) + 1` using `int_to_bytes` prepended by one byte. This is defined as

    ecpoint_to_bytes(element)

    Inputs:

    - `element`, an elliptic curve element in affine form, with attributes `x` and `y` corresponding to its affine coordinates, represented as integers modulo the coordinate field order.

    Outputs:

    A byte array

    Constants:

    field_bytes_length, the number of bytes to represent the scalar element, equal to `ceil(log2(field.order()))`.


    1. byte = 2 if sgn0(element.y) == 0 else 3
    2. return I2OSP(byte, 1) + I2OSP(x, field_bytes_length)
