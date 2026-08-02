package io.github.marcofanti.aauth.personserver.model;

/** {@code permission} is {@code "granted"} or {@code "denied"}. */
public record PermissionOutcome(String permission, String reason) {

    public static PermissionOutcome granted() {
        return new PermissionOutcome("granted", null);
    }

    public static PermissionOutcome denied(String reason) {
        return new PermissionOutcome("denied", reason);
    }
}
