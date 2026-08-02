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
        boolean secureMode) {

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
                    secureMode);
        }
    }
}
