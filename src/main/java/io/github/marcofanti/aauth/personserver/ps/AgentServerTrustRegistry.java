package io.github.marcofanti.aauth.personserver.ps;

import java.util.List;

/** Runtime registry of agent server issuers the PS trusts. */
public interface AgentServerTrustRegistry {

    List<TrustedAgentServer> listTrusted();

    void add(TrustedAgentServer entry);

    boolean remove(String issuer);

    boolean isTrusted(String issuer);
}
