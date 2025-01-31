from abc import ABC, abstractmethod
from collections import namedtuple
from sagelib.arc_groups import G, GenG, GenH, hash_to_group, hash_to_scalar
from hash_to_field import I2OSP, OS2IP, expand_message_xmd, expand_message_xof, XMDExpander, hash_to_field

from util import to_hex, to_bytes
import hashlib


class DuplexSponge(ABC):
    Unit = None

    @abstractmethod
    def __init__(self, label: bytes):
        raise NotImplementedError

    @abstractmethod
    def absorb(self, x):
        raise NotImplementedError

    @abstractmethod
    def squeeze(self, length: int):
        raise NotImplementedError


class Shake128(DuplexSponge):
    Unit = bytes

    def __init__(self, label: bytes):
        self.h = hashlib.shake_128(label)

    def absorb(self, x: bytes):
        self.h.update(x)

    def squeeze(self, length: int):
        return self.h.digest(length)

    ## trivial byte interface
    def absorb_bytes(self, bytes: bytes):
        self.h.update(bytes)
        return self

    def squeeze_bytes(self, length: int):
        return self.squeeze(length)

class Shake128GroupP384(Shake128):
    def __init__(self, label: bytes):
        from sagelib.groups import GroupP384
        super().__init__(label)
        self.GG = GroupP384()

    def absorb_scalars(self, scalars: list):
        for scalar in scalars:
            self.absorb_bytes(self.GG.serialize_scalar(scalar))
        return self

    def squeeze_scalars(self, length: int):
        byte_len = self.GG.scalar_byte_length() + 16
        scalars = []
        for _ in range(length):
            uniform_bytes = self.squeeze_bytes(byte_len)
            scalar = OS2IP(uniform_bytes) % self.GG.order()
            scalars.append(scalar)
        return scalars

    def absorb_elements(self, elements: list):
        for element in elements:
            self.absorb_bytes(self.GG.serialize(element))
        return self