package io.github.marcofanti.aauth.personserver.web;

/**
 * A draft-11 signature failure (§11.3.4): 401 whose {@code Signature-Error} header carries the
 * machine-readable {@code code}; the problem+json body repeats it with a {@code detail}.
 */
public final class SignatureError extends RuntimeException {

    /** Draft-11 §11.3.4 code not yet in the library's ErrorCodes. */
    public static final String CLOCK_SKEW = "clock_skew";

    private final String code;
    private final String acceptScheme;

    public SignatureError(String code, String detail) {
        this(code, detail, null);
    }

    /** An {@code unsupported_scheme} failure naming the scheme the endpoint accepts (§11.3.4 step 4). */
    public SignatureError(String code, String detail, String acceptScheme) {
        super(detail);
        this.code = code;
        this.acceptScheme = acceptScheme;
    }

    public String acceptScheme() {
        return acceptScheme;
    }

    public String code() {
        return code;
    }
}
