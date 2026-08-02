package io.github.marcofanti.aauth.personserver.agentserver;

import java.util.UUID;
import java.util.regex.Pattern;

/** Agent identifier generation and validation per AAuth spec (§Agent Identifiers). */
public final class AgentIds {

    private static final Pattern LOCAL_PART = Pattern.compile("^[a-z0-9\\-_.+]{1,255}$");

    private AgentIds() {}

    /** Mint a new stable agent ID: {@code aauth:<uuid>@<domain>}. */
    public static String generateAgentId(String serverDomain) {
        return "aauth:" + UUID.randomUUID() + "@" + serverDomain;
    }

    public static boolean isValidAgentId(String agentId) {
        if (!agentId.startsWith("aauth:")) {
            return false;
        }
        String rest = agentId.substring(6);
        int at = rest.lastIndexOf('@');
        if (at <= 0 || at == rest.length() - 1) {
            return false;
        }
        String local = rest.substring(0, at);
        return LOCAL_PART.matcher(local).matches();
    }
}
