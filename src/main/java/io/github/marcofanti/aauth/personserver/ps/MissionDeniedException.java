package io.github.marcofanti.aauth.personserver.ps;

/**
 * PS mission evaluator (Layer 1) decided the request falls outside mission bounds.
 * HTTP 403 {@code mission_denied}; {@code reason} carries the evaluator's explanation.
 */
public class MissionDeniedException extends PsException {

    private final String reason;

    public MissionDeniedException() {
        this("outside mission scope");
    }

    public MissionDeniedException(String reason) {
        super(reason);
        this.reason = reason;
    }

    public String reason() {
        return reason;
    }
}
