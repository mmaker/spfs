from abc import ABC, abstractmethod
from hash_to_field import OS2IP
import struct
import hashlib
from keccak import Keccak
from sagelib.groups import GroupP384

class DuplexSpongeInterface(ABC):
    Unit = None

    @abstractmethod
    def __init__(self, iv: bytes):
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
        flattened_matrix = [val for row in state for val in row]
        result = struct.pack('<25Q', *flattened_matrix)
        return bytearray(result)

    def _bytes_to_keccak_state(self, byte_array):
        flat_state = list(struct.unpack('<25Q', byte_array))
        return [flat_state[i:i+5] for i in range(0, 25, 5)]

    def permute(self):
        state = self._bytes_to_keccak_state(bytearray(self.state))
        new_state = self.p.KeccakF(state)
        self.state = self._keccak_state_to_bytes(new_state)


class DuplexSponge(DuplexSpongeInterface):
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


class Shake128(DuplexSpongeInterface):
    state = KeccakPermutationState()

    def __init__(self, iv: bytes):
        assert(len(iv) == 32)
        self.round = 0
        self.iv = iv

        self.h = self._new_oracle()


    def _new_oracle(self):
        h = hashlib.shake_128()
        h.update(self.iv)
        h.update(struct.pack('<Q', self.round))
        return h

    def absorb(self, input: bytes):
        self.h.update(input)

    def squeeze(self, length: int):
        self.round += 1
        verifier_message = self.h.digest(length)
        self.h = self._new_oracle()
        return verifier_message


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


class KeccakDuplexSpongeP384(DuplexSponge, ByteCodec, P384Codec):
    state = KeccakPermutationState()
    GG = GroupP384()

    def __init__(self, label: bytes):
        iv = hashlib.sha256(label).digest()
        super().__init__(iv)


class SHAKE128HashChainP384(Shake128, ByteCodec, P384Codec):
    GG = GroupP384()

    def __init__(self, label: bytes):
        iv = hashlib.sha256(label).digest()
        super().__init__(iv)



if __name__ == "__main__":
    label = b"yellow submarine" * 2
    sponge = SHAKE128HashChainP384(label)
    scalar = SHAKE128HashChainP384.GG.ScalarField.field(42)
    sponge.absorb_scalars([scalar])
    scalars = sponge.squeeze_scalars(1)
    print(scalars)
