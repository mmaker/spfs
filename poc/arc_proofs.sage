from sagelib.arc_groups import GenG, GenH, hash_to_group, hash_to_scalar, context_string
from sagelib.zkp import Prover, Verifier
from util import to_bytes

class CredentialRequestProof(object):
    @classmethod
    def prove(self, m1, m2, r1, r2, m1_enc, m2_enc, rng):
        prover = Prover(context_string + "CredentialRequest", rng)
        m1_var = prover.append_scalar("m1", m1)
        m2_var = prover.append_scalar("m2", m2)
        r1_var = prover.append_scalar("r1", r1)
        r2_var = prover.append_scalar("r2", r2)

        gen_G_var = prover.append_element("genG", GenG)
        gen_H_var = prover.append_element("genH", GenH)
        m1_enc_var = prover.append_element("m1Enc", m1_enc)
        m2_enc_var = prover.append_element("m2Enc", m2_enc)

        prover.constrain(m1_enc_var, [(m1_var, gen_G_var), (r1_var, gen_H_var)])
        prover.constrain(m2_enc_var, [(m2_var, gen_G_var), (r2_var, gen_H_var)])

        return prover.prove()

    @classmethod
    def verify(cls, blinded_request):
        verifier = Verifier(context_string + "CredentialRequest")

        m1_var = verifier.append_scalar("m1")
        m2_var = verifier.append_scalar("m2")
        r1_var = verifier.append_scalar("r1")
        r2_var = verifier.append_scalar("r2")
        gen_G_var = verifier.append_element("genG", GenG)
        gen_H_var = verifier.append_element("genH", GenH)
        m1_enc_var = verifier.append_element("m1Enc", blinded_request.m1_enc)
        m2_enc_var = verifier.append_element("m2Enc", blinded_request.m2_enc)

        verifier.constrain(m1_enc_var, [(m1_var, gen_G_var), (r1_var, gen_H_var)])
        verifier.constrain(m2_enc_var, [(m2_var, gen_G_var), (r2_var, gen_H_var)])
        
        return verifier.verify(blinded_request.request_proof)

class CredentialResponseProof(object):
    @classmethod
    def prove(cls, private_key, public_key, request, b, U, enc_U_prime, X0_aux, X1_aux, X2_aux, H_aux, rng):
        prover = Prover(context_string + "CredentialResponse", rng)

        x0_var = prover.append_scalar("x0", private_key.x0)
        x1_var = prover.append_scalar("x1", private_key.x1)
        x2_var = prover.append_scalar("x2", private_key.x2)
        xb_var = prover.append_scalar("x0Blinding", private_key.xb)
        b_var = prover.append_scalar("b", b)
        t1_var = prover.append_scalar("t1", b * private_key.x1)
        t2_var = prover.append_scalar("t2", b * private_key.x2)

        gen_G_var = prover.append_element("genG", GenG)
        gen_H_var = prover.append_element("genH", GenH)
        m1_enc_var = prover.append_element("m1Enc", request.m1_enc)
        m2_enc_var = prover.append_element("m2Enc", request.m2_enc)
        U_var = prover.append_element("U", U)
        enc_U_prime_var = prover.append_element("encUPrime", enc_U_prime)
        X0_var = prover.append_element("X0", public_key.X0)
        X1_var = prover.append_element("X1", public_key.X1)
        X2_var = prover.append_element("X2", public_key.X2)
        X0_aux_var = prover.append_element("X0Aux", X0_aux)
        X1_aux_var = prover.append_element("X1Aux", X1_aux)
        X2_aux_var = prover.append_element("X2Aux", X2_aux)
        H_aux_var = prover.append_element("HAux", H_aux)

        # 1. X0 = x0 * generatorG + x0Blinding * generatorH
        prover.constrain(X0_var, [(x0_var, gen_G_var), (xb_var, gen_H_var)])

        # 2. X1 = x1 * generatorH
        prover.constrain(X1_var, [(x1_var, gen_H_var)])
        
        # 3. X2 = x2 * generatorH
        prover.constrain(X2_var, [(x2_var, gen_H_var)])

        # 4. X0Aux = b * x0Blinding * generatorH
        # 4a. HAux = b * generatorH
        prover.constrain(H_aux_var, [(b_var, gen_H_var)])
        # 4b: X0Aux = x0Blinding * HAux (= b * x0Blinding * generatorH)
        prover.constrain(X0_aux_var, [(xb_var, H_aux_var)])

        # 5. X1Aux = b * x1 * generatorH
        # 5a. X1Aux = t1 * generatorH (t1 = b * x1)
        prover.constrain(X1_aux_var, [(t1_var, gen_H_var)])
        # 5b. X1Aux = b * X1 (X1 = x1 * generatorH)
        prover.constrain(X1_aux_var, [(b_var, X1_var)])

        # 6. X2Aux = b * x2 * generatorH
        # 6a. X2Aux = b * X2 (X2 = x2 * generatorH)
        prover.constrain(X2_aux_var, [(b_var, X2_var)])
        # 6b. X2Aux = t2 * H (t2 = b * x2)
        prover.constrain(X2_aux_var, [(t2_var, gen_H_var)])

        # 7. U = b * generatorG
        prover.constrain(U_var, [(b_var, gen_G_var)])
        # 8. encUPrime = b * (X0 + x1 * Enc(m1) + x2 * Enc(m2))
        # simplified: encUPrime = b * X0 + t1 * m1Enc + t2 * m2Enc, since t1 = b * x1 and t2 = b * x2
        prover.constrain(enc_U_prime_var, [(b_var, X0_var), (t1_var, m1_enc_var), (t2_var, m2_enc_var)])

        return prover.prove()

    @classmethod
    def verify(cls, public_key, response, request):
        verifier = Verifier(context_string + "CredentialResponse")

        x0_var = verifier.append_scalar("x0")
        x1_var = verifier.append_scalar("x1")
        x2_var = verifier.append_scalar("x2")
        xb_var = verifier.append_scalar("x0Blinding")
        b_var = verifier.append_scalar("b")
        t1_var = verifier.append_scalar("t1")
        t2_var = verifier.append_scalar("t2")

        gen_G_var = verifier.append_element("genG", GenG)
        gen_H_var = verifier.append_element("genH", GenH)
        m1_enc_var = verifier.append_element("m1Enc", request.m1_enc)
        m2_enc_var = verifier.append_element("m2Enc", request.m2_enc)
        U_var = verifier.append_element("U", response.U)
        enc_U_prime_var = verifier.append_element("encUPrime", response.enc_U_prime)
        X0_var = verifier.append_element("X0", public_key.X0)
        X1_var = verifier.append_element("X1", public_key.X1)
        X2_var = verifier.append_element("X2", public_key.X2)
        X0_aux_var = verifier.append_element("X0Aux", response.X0_aux)
        X1_aux_var = verifier.append_element("X1Aux", response.X1_aux)
        X2_aux_var = verifier.append_element("X2Aux", response.X2_aux)
        H_aux_var = verifier.append_element("HAux", response.H_aux)

        # 1. X0 = x0 * generatorG + x0Blinding * generatorH
        verifier.constrain(X0_var, [(x0_var, gen_G_var), (xb_var, gen_H_var)])

        # 2. X1 = x1 * generatorH
        verifier.constrain(X1_var, [(x1_var, gen_H_var)])
        
        # 3. X2 = x2 * generatorH
        verifier.constrain(X2_var, [(x2_var, gen_H_var)])

        # 4. X0Aux = b * x0Blinding * generatorH
        # 4a. HAux = b * generatorH
        verifier.constrain(H_aux_var, [(b_var, gen_H_var)])
        # 4b: X0Aux = x0Blinding * HAux (= b * x0Blinding * generatorH)
        verifier.constrain(X0_aux_var, [(xb_var, H_aux_var)])

        # 5. X1Aux = b * x1 * generatorH
        # 5a. X1Aux = t1 * generatorH (t1 = b * x1)
        verifier.constrain(X1_aux_var, [(t1_var, gen_H_var)])
        # 5b. X1Aux = b * X1 (X1 = x1 * generatorH)
        verifier.constrain(X1_aux_var, [(b_var, X1_var)])

        # 6. X2Aux = b * x2 * generatorH
        # 6a. X2Aux = b * X2 (X2 = x2 * generatorH)
        verifier.constrain(X2_aux_var, [(b_var, X2_var)])
        # 6b. X2Aux = t2 * H (t2 = b * x2)
        verifier.constrain(X2_aux_var, [(t2_var, gen_H_var)])

        # 7. U = b * generatorG
        verifier.constrain(U_var, [(b_var, gen_G_var)])
        # 8. encUPrime = b * (X0 + x1 * Enc(m1) + x2 * Enc(m2))
        # simplified: encUPrime = b * X0 + t1 * m1Enc + t2 * m2Enc, since t1 = b * x1 and t2 = b * x2
        verifier.constrain(enc_U_prime_var, [(b_var, X0_var), (t1_var, m1_enc_var), (t2_var, m2_enc_var)])

        return verifier.verify(response.response_proof)

class PresentationProof(object):
    @classmethod
    def prove(cls, U, U_prime_commit, m1_commit, tag, generator_T, credential, V, r, z, nonce, m1_tag, rng):
        prover = Prover(context_string + "CredentialPresentation", rng)

        m1_var = prover.append_scalar("m1", credential.m1)
        z_var = prover.append_scalar("z", z)
        r_neg_var = prover.append_scalar("-r", -r)
        nonce_var = prover.append_scalar("nonce", nonce)

        gen_G_var = prover.append_element("genG", GenG)
        gen_H_var = prover.append_element("genH", GenH)
        U_var = prover.append_element("U", U)
        _ = prover.append_element("UPrimeCommit", U_prime_commit)
        m1_commit_var = prover.append_element("m1Commit", m1_commit)
        V_var = prover.append_element("V", V)
        X1_var = prover.append_element("X1", credential.X1)
        tag_var = prover.append_element("tag", tag)
        gen_T_var = prover.append_element("genT", generator_T)
        m1_tag_var = prover.append_element("m1Tag", m1_tag)

        # 1. m1Commit = m1 * U + z * generatorH
        prover.constrain(m1_commit_var, [(m1_var, U_var), (z_var, gen_H_var)])
        # 2. V = z * X1 - r * generatorG
        prover.constrain(V_var, [(z_var, X1_var), (r_neg_var, gen_G_var)])
        # 3. G.HashToGroup(presentationContext, "Tag") = m1 * tag + counter * tag
        prover.constrain(gen_T_var, [(m1_var, tag_var), (nonce_var, tag_var)])
        # 4. m1Tag = m1 * tag
        prover.constrain(m1_tag_var, [(m1_var, tag_var)])

        return prover.prove()

    @classmethod
    def verify(cls, server_private_key, server_public_key, request_context, presentation_context, presentation, m1_tag):
        verifier = Verifier(context_string + "CredentialPresentation")

        m2 = hash_to_scalar(request_context, to_bytes("requestContext"))
        V = server_private_key.x0 * presentation.U + server_private_key.x1 * presentation.m1_commit + server_private_key.x2 * m2 * presentation.U - presentation.U_prime_commit
        generator_T = hash_to_group(presentation_context, to_bytes("Tag"))

        m1_var = verifier.append_scalar("m1")
        z_var = verifier.append_scalar("z")
        r_neg_var = verifier.append_scalar("-r")
        nonce_var = verifier.append_scalar("nonce")

        gen_G_var = verifier.append_element("genG", GenG)
        gen_H_var = verifier.append_element("genH", GenH)
        U_var = verifier.append_element("U", presentation.U)
        _ = verifier.append_element("UPrimeCommit", presentation.U_prime_commit)
        m1_commit_var = verifier.append_element("m1Commit", presentation.m1_commit)
        V_var = verifier.append_element("V", V)
        X1_var = verifier.append_element("X1", server_public_key.X1)
        tag_var = verifier.append_element("tag", presentation.tag)
        gen_T_var = verifier.append_element("genT", generator_T)
        m1_tag_var = verifier.append_element("m1Tag", m1_tag)

        # 1. m1Commit = m1 * U + z * generatorH
        verifier.constrain(m1_commit_var, [(m1_var, U_var), (z_var, gen_H_var)])
        # 2. V = z * X1 - r * generatorG
        verifier.constrain(V_var, [(z_var, X1_var), (r_neg_var, gen_G_var)])
        # 3. G.HashToGroup(presentationContext, "Tag") = m1 * tag + counter * tag
        verifier.constrain(gen_T_var, [(m1_var, tag_var), (nonce_var, tag_var)])
        # 4. Statements for the range proof that counter is in [0, rateLimit)
        verifier.constrain(m1_tag_var, [(m1_var, tag_var)])

        return verifier.verify(presentation.proof)