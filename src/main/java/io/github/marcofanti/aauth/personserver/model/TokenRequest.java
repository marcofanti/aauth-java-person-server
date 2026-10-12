package io.github.marcofanti.aauth.personserver.model;

import java.util.Map;

/**
 * Agent request to {@code POST /token}.
 *
 * <p>{@code agentCnfJwk}/{@code agentJkt} are populated for secure {@code POST /token}
 * (scheme=jwt) and required to issue {@code aa-auth+jwt}. When {@code secureMode} is false,
 * resource-token verification is skipped ({@code AAUTH_PS_INSECURE_DEV} demo path).
 */
public record TokenRequest(
        String agentId,
        String resourceToken,
        String justification,
        String upstreamToken,
        String loginHint,
        String tenant,
        String domainHint,
        MissionRef mission,
        Map<String, Object> agentCnfJwk,
        String agentJkt,
        boolean secureMode,
        Draft11 draft11) {

    /**
     * Draft-11 request context (§7.2.1); {@code null} for a draft-10 request. {@code presentedToken}
     * is the person or auth token the agent presented to the resource.
     */
    public record Draft11(String presentedToken, Long agentTokenExp) {}

    /** The same request bound to {@code missionRef} (draft-11: taken from the verified resource token). */
    public TokenRequest withMission(MissionRef missionRef) {
        return new TokenRequest(
                agentId,
                resourceToken,
                justification,
                upstreamToken,
                loginHint,
                tenant,
                domainHint,
                missionRef,
                agentCnfJwk,
                agentJkt,
                secureMode,
                draft11);
    }

    /** The same request with an updated resource token (§7.5.2.2), keeping every other field. */
    public TokenRequest withUpdatedRequest(String newResourceToken, String newJustification, String presentedToken) {
        Draft11 updated = draft11 == null ? null : new Draft11(presentedToken, draft11.agentTokenExp());
        return new TokenRequest(
                agentId,
                newResourceToken,
                newJustification,
                upstreamToken,
                loginHint,
                tenant,
                domainHint,
                mission,
                agentCnfJwk,
                agentJkt,
                secureMode,
                updated);
    }

    public static Builder builder(String agentId, String resourceToken) {
        return new Builder(agentId, resourceToken);
    }

    public static final class Builder {
        private final String agentId;
        private final String resourceToken;
        private String justification;
        private String upstreamToken;
        private String loginHint;
        private String tenant;
        private String domainHint;
        private MissionRef mission;
        private Map<String, Object> agentCnfJwk;
        private String agentJkt;
        private boolean secureMode = true;
        private Draft11 draft11;

        private Builder(String agentId, String resourceToken) {
            this.agentId = agentId;
            this.resourceToken = resourceToken;
        }

        public Builder justification(String justification) {
            this.justification = justification;
            return this;
        }

        public Builder upstreamToken(String upstreamToken) {
            this.upstreamToken = upstreamToken;
            return this;
        }

        public Builder loginHint(String loginHint) {
            this.loginHint = loginHint;
            return this;
        }

        public Builder tenant(String tenant) {
            this.tenant = tenant;
            return this;
        }

        public Builder domainHint(String domainHint) {
            this.domainHint = domainHint;
            return this;
        }

        public Builder mission(MissionRef mission) {
            this.mission = mission;
            return this;
        }

        public Builder agentCnfJwk(Map<String, Object> agentCnfJwk) {
            this.agentCnfJwk = agentCnfJwk;
            return this;
        }

        public Builder agentJkt(String agentJkt) {
            this.agentJkt = agentJkt;
            return this;
        }

        public Builder secureMode(boolean secureMode) {
            this.secureMode = secureMode;
            return this;
        }

        public Builder draft11(Draft11 draft11) {
            this.draft11 = draft11;
            return this;
        }

        public TokenRequest build() {
            return new TokenRequest(
                    agentId,
                    resourceToken,
                    justification,
                    upstreamToken,
                    loginHint,
                    tenant,
                    domainHint,
                    mission,
                    agentCnfJwk,
                    agentJkt,
                    secureMode,
                    draft11);
        }
    }
}
