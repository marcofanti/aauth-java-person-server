package io.github.marcofanti.aauth.personserver.model;

/** Deferred response body {@code status} (protocol §Pending Response). */
public enum PendingStatus {
    PENDING("pending"),
    INTERACTING("interacting");

    private final String value;

    PendingStatus(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    public static PendingStatus fromValue(String value) {
        for (PendingStatus status : values()) {
            if (status.value.equals(value)) {
                return status;
            }
        }
        throw new IllegalArgumentException("unknown pending status: " + value);
    }
}
