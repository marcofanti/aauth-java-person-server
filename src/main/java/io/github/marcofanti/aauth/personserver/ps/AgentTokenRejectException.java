package io.github.marcofanti.aauth.personserver.ps;

/** Invalid agent HTTP signature or {@code aa-agent+jwt} on secure {@code POST /token}. */
public class AgentTokenRejectException extends PsException {

    private final String error;

    public AgentTokenRejectException(String message, String error) {
        super(message);
        this.error = error;
    }

    public String error() {
        return error;
    }
}
