package io.github.marcofanti.aauth.personserver.web;

/**
 * A draft-11 signature failure (§11.3.4): 401 whose {@code Signature-Error} header carries the
 * machine-readable {@code code}; the problem+json body repeats it with a {@code detail}.
 */
public final class SignatureError extends RuntimeException {

    private final String code;

    public SignatureError(String code, String detail) {
        super(detail);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
