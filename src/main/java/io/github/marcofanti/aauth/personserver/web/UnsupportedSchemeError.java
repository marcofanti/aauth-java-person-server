package io.github.marcofanti.aauth.personserver.web;

/**
 * 401 for a {@code Signature-Key} scheme this server does not accept. Rendered with the
 * draft-10 posture headers ({@code Signature-Error}, {@code Accept-Signature-Scheme},
 * {@code Accept-Signature-Alg}) so agents can renegotiate.
 */
public final class UnsupportedSchemeError extends HttpError {

    public UnsupportedSchemeError(String detail) {
        super(401, detail);
    }
}
