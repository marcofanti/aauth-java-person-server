package io.github.marcofanti.aauth.personserver.ps.web;

import io.github.marcofanti.aauth.personserver.ps.web.HttpSigAuth.SignedRequest;
import io.github.marcofanti.aauth.personserver.web.SignatureError;
import io.github.marcofanti.aauth.signing.HttpSignatureException;
import io.github.marcofanti.aauth.signing.SignatureBase;
import io.github.marcofanti.aauth.signing.SignatureInputHeader;
import java.util.List;

/**
 * Draft-11 §11.3.3 (PS-101): every signed request with a body must cover {@code content-digest}
 * and {@code content-type}, and the digest must match the body. Applied on draft-11 endpoints;
 * draft-10 endpoints keep the reference behavior.
 */
public final class BodyCoverage {

    private static final List<String> REQUIRED = List.of("content-digest", "content-type");

    private BodyCoverage() {}

    public static void require(SignedRequest request) {
        byte[] body = request.body();
        if (body == null || body.length == 0) {
            return;
        }
        String signatureInput = request.header("signature-input");
        if (signatureInput == null) {
            throw new SignatureError("invalid_signature", "Signature-Input is missing");
        }
        List<String> covered;
        try {
            covered = SignatureInputHeader.parse(signatureInput).components();
        } catch (HttpSignatureException | IllegalArgumentException e) {
            throw new SignatureError("invalid_signature", "Signature-Input is missing or malformed");
        }
        if (!covered.containsAll(REQUIRED)) {
            throw new SignatureError(
                    "invalid_input", "a request with a body must cover content-digest and content-type (§11.3.3)");
        }
        String digest = request.header("content-digest");
        if (digest == null || SignatureBase.verifyContentDigest(digest, body) != SignatureBase.DigestCheck.MATCH) {
            throw new SignatureError("invalid_signature", "Content-Digest does not match the request body");
        }
    }
}
