from abc import ABC, abstractmethod
from collections import namedtuple
from hash_to_field import I2OSP, OS2IP, expand_message_xmd, expand_message_xof, XMDExpander, hash_to_field

from util import to_hex, to_bytes
import hashlib
from keccak import Keccak
from sagelib.groups import GroupP384

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


class KeccakPermutationState:
    R = 136    # rate
    N = 136 + 64    # rate + capacity

    def __init__(self):
        self.state = bytearray(200)
        self.p = Keccak(1600)

    def __getitem__(self, i):
        return self.state[i]

    def __setitem__(self, i, value):
        self.state[i] = value

    def _keccak_state_to_bytes(self, state):
        import struct
        result = b''
        for y in range(5):
            for x in range(5):
                result += struct.pack("<Q", state[x][y])
        assert len(result) == 200
        return bytearray(result)

    def _bytes_to_keccak_state(self, byte_array):
        assert len(byte_array) == 200
        state = [[0 for _ in range(5)] for _ in range(5)]
        for y in range(5):
            for x in range(5):
                lane = 0
                # Convert 8 bytes to a 64-bit lane (little-endian)
                for i in range(8):
                    # Calculate position in the input byte array
                    pos = 8 * (5 * y + x) + i
                    # Shift and OR the byte into the appropriate position in the 64-bit lane
                    lane |= (byte_array[pos] & 0xFF) << (8 * i)
                # Store the lane in the state array
                state[x][y] = lane
        return state

    def permute(self):
        state = self._bytes_to_keccak_state(bytearray(self.state))
        new_state = self.p.KeccakF(state)
        self.state = self._keccak_state_to_bytes(new_state)


class DuplexSponge:
    state = None

    def __init__(self, iv: bytes):
        assert len(iv) == 32
        self.absorb_index = 0
        self.squeeze_index = 0
        self.rate = self.state.R
        self.capacity = self.state.N - self.state.R

    def absorb(self, input: bytes):
        self.squeeze_index = self.rate
        if len(input) == 0:
            return

        if 0 <= self.absorb_index < self.rate:
            self.state[self.absorb_index] = input[0]
            self.absorb_index += 1
            input = input[1:]
            return self.absorb(input)

        if self.absorb_index == self.rate:
            self.state.permute()
            self.absorb_index = 0
            return self.absorb(input)

    def squeeze(self, length: int):
        self.absorb_index = self.rate

        output = b''
        if length == 0:
            return output

        if 0 <= self.squeeze_index < self.rate:
            output += bytes(self.state[self.squeeze_index:self.squeeze_index+1])
            self.squeeze_index += 1
            length -= 1
            return output + self.squeeze(length)

        if self.squeeze_index == self.rate:
            self.state.permute()
            self.squeeze_index = 0
            return output + self.squeeze(length)


class ByteCodec:
    def absorb_bytes(self, bytes: bytes):
        return self.absorb(bytes)

    def squeeze_bytes(self, length: int):
        return self.squeeze(length)

class P384Codec:
    GG = None

    def absorb_scalars(self, scalars: list):
        self.absorb_bytes(self.GG.ScalarField.serialize(scalars))

    def squeeze_scalars(self, length: int):
        byte_len = self.GG.ScalarField.scalar_byte_length() + 16
        scalars = []
        for _ in range(length):
            uniform_bytes = self.squeeze_bytes(byte_len)
            scalar = OS2IP(uniform_bytes) % self.GG.order()
            scalars.append(scalar)
        return scalars

    def absorb_elements(self, elements: list):
        self.absorb_bytes(self.GG.serialize(elements))
        return self


class DuplexSpongeKeccakP384(DuplexSponge, ByteCodec, P384Codec):
    state = KeccakPermutationState()
    GG = GroupP384()

    def __init__(self, label: bytes):
        iv = hashlib.sha256(label).digest()
        super().__init__(iv)

if __name__ == "__main__":
    label = b"yellow submarine" * 2
    sponge = DuplexSpongeKeccakP384(label)
    scalar = DuplexSpongeKeccakP384.GG.ScalarField.field(42)
    sponge.absorb_scalars([scalar])
    scalars = sponge.squeeze_scalars(1)
    print(scalars)
