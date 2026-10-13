package io.github.marcofanti.aauth.personserver.ps;

/** Invalid agent HTTP signature or {@code aa-agent+jwt} on secure {@code POST /token}. */
public class AgentTokenRejectException extends PsException {

    /** Draft-10 codes; draft-11 reports agent-token failures through {@code Signature-Error} instead. */
    public static final String EXPIRED_AGENT_TOKEN = "expired_agent_token";

    public static final String INVALID_AGENT_TOKEN = "invalid_agent_token";

    private final String error;

    public AgentTokenRejectException(String message, String error) {
        super(message);
        this.error = error;
    }

    public String error() {
        return error;
    }
}
