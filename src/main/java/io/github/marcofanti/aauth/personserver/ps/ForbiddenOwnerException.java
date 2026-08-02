package io.github.marcofanti.aauth.personserver.ps;

/** Mission not owned by the authenticated legal user; HTTP 403. */
public class ForbiddenOwnerException extends PsException {

    public ForbiddenOwnerException() {
        super("forbidden");
    }
}
