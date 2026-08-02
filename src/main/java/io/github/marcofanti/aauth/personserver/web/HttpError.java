package io.github.marcofanti.aauth.personserver.web;

/** Port of FastAPI's {@code HTTPException}: a status code plus a {@code detail} string. */
public class HttpError extends RuntimeException {

    private final int status;

    public HttpError(int status, String detail) {
        super(detail);
        this.status = status;
    }

    public int status() {
        return status;
    }

    public String detail() {
        return getMessage();
    }
}
