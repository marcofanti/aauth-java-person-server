package io.github.marcofanti.aauth.personserver.ps;

/** Invalid or expired resource token on {@code POST /token} (secure mode). */
public class ResourceTokenRejectException extends PsException {

    private final String error;

    public ResourceTokenRejectException(String message, String error) {
        super(message);
        this.error = error;
    }

    public String error() {
        return error;
    }
}
