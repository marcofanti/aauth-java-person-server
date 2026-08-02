package io.github.marcofanti.aauth.personserver.model;

/** Mission lifecycle (SPEC §Mission Management): active or terminated. */
public enum MissionState {
    ACTIVE("active"),
    TERMINATED("terminated");

    private final String value;

    MissionState(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    public static MissionState fromValue(String value) {
        for (MissionState state : values()) {
            if (state.value.equals(value)) {
                return state;
            }
        }
        throw new IllegalArgumentException("unknown mission state: " + value);
    }
}
