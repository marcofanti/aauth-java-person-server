package io.github.marcofanti.aauth.personserver.model;

import java.util.List;
import java.util.Map;

/**
 * What the consent UI shows the user for a pending decision.
 *
 * <p>{@code pendingKind} is {@code "token" | "mission" | "interaction"} — which deferred flow
 * this consent is for. The {@code resource*} fields come from a verified {@code aa-resource+jwt}
 * (mode 3); the {@code permission*} fields are set when the user is deciding a permission
 * request (Layer 2 — approved-tools gating); {@code evaluatorReason} is PS-evaluator guidance
 * (Layer 1 — mission-aware decisions).
 */
public record ConsentContext(
        String pendingId,
        String resourceName,
        Map<String, String> scopes,
        String justification,
        Mission mission,
        String agentName,
        List<String> clarificationResponses,
        String interactionType,
        String summary,
        String question,
        String pendingKind,
        String resourceIss,
        String resourceScope,
        String resourceMissionS256,
        String permissionAction,
        String permissionDescription,
        Map<String, Object> permissionParameters,
        String evaluatorReason) {

    public static Builder builder(String pendingId) {
        return new Builder(pendingId);
    }

    public static final class Builder {
        private final String pendingId;
        private String resourceName;
        private Map<String, String> scopes = Map.of();
        private String justification;
        private Mission mission;
        private String agentName;
        private List<String> clarificationResponses = List.of();
        private String interactionType;
        private String summary;
        private String question;
        private String pendingKind;
        private String resourceIss;
        private String resourceScope;
        private String resourceMissionS256;
        private String permissionAction;
        private String permissionDescription;
        private Map<String, Object> permissionParameters;
        private String evaluatorReason;

        private Builder(String pendingId) {
            this.pendingId = pendingId;
        }

        public Builder resourceName(String resourceName) {
            this.resourceName = resourceName;
            return this;
        }

        public Builder scopes(Map<String, String> scopes) {
            this.scopes = scopes;
            return this;
        }

        public Builder justification(String justification) {
            this.justification = justification;
            return this;
        }

        public Builder mission(Mission mission) {
            this.mission = mission;
            return this;
        }

        public Builder agentName(String agentName) {
            this.agentName = agentName;
            return this;
        }

        public Builder clarificationResponses(List<String> clarificationResponses) {
            this.clarificationResponses = clarificationResponses;
            return this;
        }

        public Builder interactionType(String interactionType) {
            this.interactionType = interactionType;
            return this;
        }

        public Builder summary(String summary) {
            this.summary = summary;
            return this;
        }

        public Builder question(String question) {
            this.question = question;
            return this;
        }

        public Builder pendingKind(String pendingKind) {
            this.pendingKind = pendingKind;
            return this;
        }

        public Builder resourceIss(String resourceIss) {
            this.resourceIss = resourceIss;
            return this;
        }

        public Builder resourceScope(String resourceScope) {
            this.resourceScope = resourceScope;
            return this;
        }

        public Builder resourceMissionS256(String resourceMissionS256) {
            this.resourceMissionS256 = resourceMissionS256;
            return this;
        }

        public Builder permissionAction(String permissionAction) {
            this.permissionAction = permissionAction;
            return this;
        }

        public Builder permissionDescription(String permissionDescription) {
            this.permissionDescription = permissionDescription;
            return this;
        }

        public Builder permissionParameters(Map<String, Object> permissionParameters) {
            this.permissionParameters = permissionParameters;
            return this;
        }

        public Builder evaluatorReason(String evaluatorReason) {
            this.evaluatorReason = evaluatorReason;
            return this;
        }

        public ConsentContext build() {
            return new ConsentContext(
                    pendingId,
                    resourceName,
                    scopes,
                    justification,
                    mission,
                    agentName,
                    clarificationResponses,
                    interactionType,
                    summary,
                    question,
                    pendingKind,
                    resourceIss,
                    resourceScope,
                    resourceMissionS256,
                    permissionAction,
                    permissionDescription,
                    permissionParameters,
                    evaluatorReason);
        }
    }
}
