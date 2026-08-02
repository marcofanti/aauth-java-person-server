package io.github.marcofanti.aauth.personserver.model;

public record UserDecision(boolean approved, String clarificationQuestion, String answerText) {

    public UserDecision(boolean approved) {
        this(approved, null, null);
    }
}
