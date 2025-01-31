from sagelib.groups import GroupP384
from sagelib.arc_proofs import CredentialRequestProof, CredentialResponseProof, PresentationProof
from sagelib.arc_groups import G, GenG, GenH, hash_to_group, hash_to_scalar
from util import to_hex, to_bytes

from collections import namedtuple
ClientSecrets = namedtuple("ClientSecrets", "m1 m2 r1 r2")
BlindedRequest = namedtuple("BlindedRequest", "m1_enc m2_enc request_proof")
BlindedResponse = namedtuple("BlindedResponse", "U enc_U_prime X0_aux X1_aux X2_aux H_aux response_proof")
PresentationInputs = namedtuple("PresentationInputs", "U U_prime_commit m_commit")
PresentationProofInputs = namedtuple("PresentationProofInputs", "V r z")

class Presentation(object):
    def __init__(self, U, U_prime_commit, m1_commit, nonce, tag, proof):
        self.U = U
        self.U_prime_commit = U_prime_commit
        self.m1_commit = m1_commit
        self.nonce = nonce
        self.tag = tag
        self.proof = proof

class Credential(object):
    def __init__(self, m1, U, U_prime, X1):
        self.m1 = m1
        self.U = U
        self.U_prime = U_prime
        self.X1 = X1
    
class PresentationState(object):
    def __init__(self, credential, presentation_context, presentation_limit):
        self.credential = credential
        self.presentation_context = presentation_context
        self.presentation_limit = presentation_limit
        self.presentation_nonce_set = []

    def present(self, rng, vectors):
        if len(self.presentation_nonce_set) >= self.presentation_limit:
            raise Exception("LimitExceededError")

        a = G.random_scalar(rng)
        r = G.random_scalar(rng)
        z = G.random_scalar(rng)

        U = a * self.credential.U
        U_prime = a * self.credential.U_prime
        U_prime_commit = U_prime + r * GenG
        m1_commit = self.credential.m1 * U + z * GenH

        # Note: this should be randomized, but it starts
        # at 0 and increments for determinism's sake
        nonce = len(self.presentation_nonce_set)
        self.presentation_nonce_set.append(nonce)

        generator_T = hash_to_group(self.presentation_context, to_bytes("Tag"))
        tag = inverse_mod(self.credential.m1 + nonce, GroupP384().order()) * generator_T
        V = (z * self.credential.X1) - (r * GenG)
        m1_tag = self.credential.m1 * tag
        
        proof = PresentationProof.prove(U, U_prime_commit, m1_commit, tag, generator_T, self.credential, V, r, z, nonce, m1_tag, rng)
        presentation = Presentation(U, U_prime_commit, m1_commit, nonce, tag, proof)

        vectors["presentation_context"] = to_hex(self.presentation_context)
        vectors["a"] = to_hex(G.serialize_scalar(a))
        vectors["r"] = to_hex(G.serialize_scalar(r))
        vectors["z"] = to_hex(G.serialize_scalar(z))
        vectors["U"] = to_hex(G.serialize(U))
        vectors["U_prime_commit"] = to_hex(G.serialize(U_prime_commit))
        vectors["m1_commit"] = to_hex(G.serialize(m1_commit))
        vectors["nonce"] = hex(nonce)
        vectors["tag"] = to_hex(G.serialize(tag))
        vectors["proof"] = to_hex(proof.serialize())

        return presentation

class CredentialRequest(object):
    def __init__(self, blinded_request, proof):
        self.blinded_request = blinded_request
        self.proof = proof

    def serialize(self):
        return G.serialize(self.blinded_request.pk) + G.serialize(self.blinded_request.r0) + G.serialize(self.blinded_request.r1)

class CredentialRequestContext(object):
    def __init__(self, client_secrets, request):
        self.client_secrets = client_secrets
        self.request = request

    def finalize_credential(self, blinded_response, server_public_key, vectors):
        if CredentialResponseProof.verify(server_public_key, blinded_response, self.request) == False:
            raise Exception("verify_issuance_proof failed")

        U_prime = blinded_response.enc_U_prime - blinded_response.X0_aux - self.client_secrets.r1 * blinded_response.X1_aux - self.client_secrets.r2 * blinded_response.X2_aux

        vectors["m1"] = to_hex(G.serialize_scalar(self.client_secrets.m1))
        vectors["U"] = to_hex(G.serialize(blinded_response.U))
        vectors["U_prime"] = to_hex(G.serialize(U_prime))
        vectors["X1"] = to_hex(G.serialize(server_public_key.X1))

        return Credential(self.client_secrets.m1, blinded_response.U, U_prime, server_public_key.X1)

class CredentialResponse(object):
    def __init__(self, U, u0, u1, T, proof):
        self.U = U
        self.u0 = u0
        self.u1 = u1
        self.T = T
        self.proof = proof

class ClientPrivateKey(object):
    def __init__(self, rng, private_info):
        self.sk = G.random_scalar(rng)
        self.private_attr = hash_to_scalar(private_info, to_bytes("private"))
        self.pk = self.sk * GenG

    def serialize(self):
        return G.serialize_scalar(self.sk) + G.serialize_scalar(self.private_attr)

class Client(object):
    def __init__(self, rng):
        self.rng = rng

    def request(self, request_context, vectors):
        m1 = G.random_scalar(self.rng)
        m2 = hash_to_scalar(request_context, to_bytes("requestContext"))
        r1 = G.random_scalar(self.rng)
        r2 = G.random_scalar(self.rng)

        m1_enc = m1 * GenG + r1 * GenH
        m2_enc = m2 * GenG + r2 * GenH

        proof = CredentialRequestProof.prove(m1, m2, r1, r2, m1_enc, m2_enc, self.rng)
        blinded_request = BlindedRequest(m1_enc, m2_enc, proof)
        
        client_secrets = ClientSecrets(m1, m2, r1, r2)

        context = CredentialRequestContext(client_secrets, blinded_request)

        vectors["request_context"] = to_hex(request_context)
        vectors["m1"] = to_hex(G.serialize_scalar(m1))
        vectors["m2"] = to_hex(G.serialize_scalar(m2))
        vectors["r1"] = to_hex(G.serialize_scalar(r1))
        vectors["r2"] = to_hex(G.serialize_scalar(r2))
        vectors["m1_enc"] = to_hex(G.serialize(m1_enc))
        vectors["m2_enc"] = to_hex(G.serialize(m2_enc))
        vectors["proof"] = to_hex(proof.serialize())

        return context

class ServerPublicKey(object):
    def __init__(self, X0, X1, X2):
        self.X0 = X0
        self.X1 = X1
        self.X2 = X2

class ServerPrivateKey(object):
    def __init__(self, x0, x1, x2, xb):
        self.x0 = x0
        self.x1 = x1
        self.x2 = x2
        self.xb = xb

class Server(object):
    @classmethod
    def keygen(cls, rng, vectors):
        x0 = G.random_scalar(rng)
        x1 = G.random_scalar(rng)
        x2 = G.random_scalar(rng)
        xb = G.random_scalar(rng)
        X0 = (x0 * GenG) + (xb * GenH)
        X1 = (x1 * GenH)
        X2 = (x2 * GenH)

        vectors["x0"] = to_hex(G.serialize_scalar(x0))
        vectors["x1"] = to_hex(G.serialize_scalar(x1))
        vectors["x2"] = to_hex(G.serialize_scalar(x2))
        vectors["xb"] = to_hex(G.serialize_scalar(xb))
        vectors["X0"] = to_hex(G.serialize(X0))
        vectors["X1"] = to_hex(G.serialize(X1))
        vectors["X2"] = to_hex(G.serialize(X2))

        return ServerPrivateKey(x0, x1, x2, xb), ServerPublicKey(X0, X1, X2)

    def __init__(self):
        pass

    def issue(self, private_key, public_key, blinded_request, rng, vectors):
        if CredentialRequestProof.verify(blinded_request) == False:
            raise Exception("request proof verification failed")
        
        b = G.random_scalar(rng)
        U = b * GenG

        enc_U_prime = b * (public_key.X0 + private_key.x1 * blinded_request.m1_enc + private_key.x2 * blinded_request.m2_enc)
        X0_aux = b * private_key.xb * GenH
        X1_aux = b * public_key.X1
        X2_aux = b * public_key.X2
        H_aux = b * GenH

        response_proof = CredentialResponseProof.prove(private_key, public_key, blinded_request, b, U, enc_U_prime, X0_aux, X1_aux, X2_aux, H_aux, rng)
        response = BlindedResponse(U, enc_U_prime, X0_aux, X1_aux, X2_aux, H_aux, response_proof)

        vectors["b"] = to_hex(G.serialize_scalar(b))
        vectors["U"] = to_hex(G.serialize(U))
        vectors["enc_U_prime"] = to_hex(G.serialize(enc_U_prime))
        vectors["X0_aux"] = to_hex(G.serialize(X0_aux))
        vectors["X1_aux"] = to_hex(G.serialize(X1_aux))
        vectors["X2_aux"] = to_hex(G.serialize(X2_aux))
        vectors["H_aux"] = to_hex(G.serialize(H_aux))
        vectors["proof"] = to_hex(response_proof.serialize())

        return response
    
    def verify_presentation(self, private_key, public_key, request_context, presentation_context, presentation, presentation_limit):
        if presentation.nonce < 0 or presentation.nonce >= presentation_limit:
            raise Exception("InvalidNonce")
        
        generator_T = hash_to_group(presentation_context, to_bytes("Tag"))
        m1_tag = generator_T - (presentation.nonce * presentation.tag)
        return PresentationProof.verify(private_key, public_key, request_context, presentation_context, presentation, m1_tag)


