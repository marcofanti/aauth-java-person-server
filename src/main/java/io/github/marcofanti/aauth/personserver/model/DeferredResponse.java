package io.github.marcofanti.aauth.personserver.model;

import java.util.List;

/** Deferred (202) response body (protocol §Pending Response). */
public record DeferredResponse(
        String pendingId,
        String pendingUrl,
        int retryAfter,
        RequirementLevel requirement,
        String interactionUrl,
        String code,
        String clarification,
        Integer timeout,
        List<String> options,
        PendingStatus status)
        implements TokenOutcome, MissionOutcome, PendingPollOutcome, PendingStoreValue {

    public static Builder builder(String pendingId, String pendingUrl, int retryAfter) {
        return new Builder(pendingId, pendingUrl, retryAfter);
    }

    public Builder toBuilder() {
        Builder builder = new Builder(pendingId, pendingUrl, retryAfter);
        builder.requirement = requirement;
        builder.interactionUrl = interactionUrl;
        builder.code = code;
        builder.clarification = clarification;
        builder.timeout = timeout;
        builder.options = options;
        builder.status = status;
        return builder;
    }

    public static final class Builder {
        private final String pendingId;
        private final String pendingUrl;
        private final int retryAfter;
        private RequirementLevel requirement;
        private String interactionUrl;
        private String code;
        private String clarification;
        private Integer timeout;
        private List<String> options;
        private PendingStatus status = PendingStatus.PENDING;

        private Builder(String pendingId, String pendingUrl, int retryAfter) {
            this.pendingId = pendingId;
            this.pendingUrl = pendingUrl;
            this.retryAfter = retryAfter;
        }

        public Builder requirement(RequirementLevel requirement) {
            this.requirement = requirement;
            return this;
        }

        public Builder interactionUrl(String interactionUrl) {
            this.interactionUrl = interactionUrl;
            return this;
        }

        public Builder code(String code) {
            this.code = code;
            return this;
        }

        public Builder clarification(String clarification) {
            this.clarification = clarification;
            return this;
        }

        public Builder timeout(Integer timeout) {
            this.timeout = timeout;
            return this;
        }

        public Builder options(List<String> options) {
            this.options = options;
            return this;
        }

        public Builder status(PendingStatus status) {
            this.status = status;
            return this;
        }

        public DeferredResponse build() {
            return new DeferredResponse(
                    pendingId,
                    pendingUrl,
                    retryAfter,
                    requirement,
                    interactionUrl,
                    code,
                    clarification,
                    timeout,
                    options,
                    status);
        }
    }
}
