package io.github.marcofanti.aauth.personserver.web;

/** Request body failed parsing or validation (FastAPI's {@code RequestValidationError}). */
public class BodyValidationException extends RuntimeException {

    public BodyValidationException(String message) {
        super(message);
    }
}
