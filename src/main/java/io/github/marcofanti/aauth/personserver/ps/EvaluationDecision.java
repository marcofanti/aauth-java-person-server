package io.github.marcofanti.aauth.personserver.ps;

/**
 * Outcome of a mission evaluation. {@code clarificationQuestion} is the question to send
 * back to the agent when {@code decision == CLARIFY}.
 */
public record EvaluationDecision(Decision decision, String reason, String clarificationQuestion) {

    public enum Decision {
        ALLOW("allow"),
        ESCALATE("escalate"),
        CLARIFY("clarify"),
        DENY("deny");

        private final String value;

        Decision(String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }
    }

    public static EvaluationDecision allow(String reason) {
        return new EvaluationDecision(Decision.ALLOW, reason, null);
    }

    public static EvaluationDecision escalate(String reason) {
        return new EvaluationDecision(Decision.ESCALATE, reason, null);
    }

    public static EvaluationDecision clarify(String question) {
        return clarify(question, "");
    }

    public static EvaluationDecision clarify(String question, String reason) {
        return new EvaluationDecision(Decision.CLARIFY, reason.isEmpty() ? question : reason, question);
    }

    public static EvaluationDecision deny(String reason) {
        return new EvaluationDecision(Decision.DENY, reason, null);
    }
}
