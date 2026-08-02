package io.github.marcofanti.aauth.personserver.model;

/** Categories for mission log entries. */
public enum MissionLogKind {
    MISSION_APPROVED("mission_approved"),
    TOKEN_REQUEST("token_request"),
    PERMISSION("permission"),
    AUDIT("audit"),
    AGENT_INTERACTION("agent_interaction"),
    CLARIFICATION("clarification");

    private final String value;

    MissionLogKind(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    public static MissionLogKind fromValue(String value) {
        for (MissionLogKind kind : values()) {
            if (kind.value.equals(value)) {
                return kind;
            }
        }
        throw new IllegalArgumentException("unknown mission log kind: " + value);
    }
}
