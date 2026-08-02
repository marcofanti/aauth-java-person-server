package io.github.marcofanti.aauth.personserver.model;

/** AAuth-Requirement {@code requirement} values (protocol §Requirement Levels). */
public enum RequirementLevel {
    INTERACTION("interaction"),
    APPROVAL("approval"),
    AUTH_TOKEN("auth-token"),
    CLARIFICATION("clarification"),
    CLAIMS("claims");

    private final String value;

    RequirementLevel(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    public static RequirementLevel fromValue(String value) {
        for (RequirementLevel level : values()) {
            if (level.value.equals(value)) {
                return level;
            }
        }
        throw new IllegalArgumentException("unknown requirement level: " + value);
    }
}
