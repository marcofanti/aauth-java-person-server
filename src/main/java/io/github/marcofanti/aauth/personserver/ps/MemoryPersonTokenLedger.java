package io.github.marcofanti.aauth.personserver.ps;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** In-memory {@link PersonTokenLedger} (dev / tests). */
public final class MemoryPersonTokenLedger implements PersonTokenLedger {

    private final Set<String> approvals = new HashSet<>();
    private final Map<String, Issued> issued = new LinkedHashMap<>();
    private final Map<String, Map<String, Presentation>> presentations = new LinkedHashMap<>();
    private final Map<String, String> upstreams = new LinkedHashMap<>();
    private final ExpiredRecords expired = new ExpiredRecords();

    private static String approvalKey(String person, String resource) {
        return person + "\u0000" + MissionUtils.stripTrailingSlash(resource);
    }

    @Override
    public synchronized boolean isApproved(String person, String resource) {
        return approvals.contains(approvalKey(person, resource));
    }

    @Override
    public synchronized void approve(String person, String resource) {
        approvals.add(approvalKey(person, resource));
    }

    @Override
    public synchronized void recordIssued(Issued record) {
        issued.put(record.jti(), record);
        long cutoff = expired.cutoffIfDue();
        if (cutoff >= 0) {
            purgeExpired(cutoff);
        }
    }

    @Override
    public synchronized Issued findByJti(String jti) {
        return issued.get(jti);
    }

    @Override
    public synchronized void recordPresentation(String jti, String asIssuer, String agentJkt) {
        String issuer = MissionUtils.stripTrailingSlash(asIssuer);
        presentations
                .computeIfAbsent(jti, key -> new LinkedHashMap<>())
                .putIfAbsent(issuer, new Presentation(issuer, agentJkt));
    }

    @Override
    public synchronized List<Presentation> presentations(String jti) {
        return List.copyOf(presentations.getOrDefault(jti, Map.of()).values());
    }

    @Override
    public synchronized void recordUpstream(String jti, String upstreamIss, String upstreamJti) {
        upstreams.put(jti, upstreamKey(upstreamIss, upstreamJti));
    }

    @Override
    public synchronized List<Issued> issuedFromUpstream(String upstreamIss, String upstreamJti) {
        String key = upstreamKey(upstreamIss, upstreamJti);
        List<Issued> out = new ArrayList<>();
        upstreams.forEach((jti, upstream) -> {
            if (upstream.equals(key) && issued.containsKey(jti)) {
                out.add(issued.get(jti));
            }
        });
        return out;
    }

    private static String upstreamKey(String iss, String jti) {
        return MissionUtils.stripTrailingSlash(iss) + "\u0000" + jti;
    }

    @Override
    public synchronized List<Issued> findBySubject(String aud, String sub) {
        String resource = MissionUtils.stripTrailingSlash(aud);
        List<Issued> out = new ArrayList<>();
        for (Issued record : issued.values()) {
            if (record.aud().equals(resource) && record.sub().equals(sub)) {
                out.add(record);
            }
        }
        return out;
    }

    @Override
    public synchronized List<Issued> liveFor(String agentId, long nowEpochSeconds) {
        List<Issued> out = new ArrayList<>();
        for (Issued record : issued.values()) {
            if (record.agentId().equals(agentId) && record.exp() > nowEpochSeconds) {
                out.add(record);
            }
        }
        return out;
    }

    @Override
    public synchronized int distinctLiveResources(String agentId, String exclude, long nowEpochSeconds) {
        String excluded = MissionUtils.stripTrailingSlash(exclude);
        Set<String> resources = new HashSet<>();
        for (Issued record : issued.values()) {
            if (record.agentId().equals(agentId)
                    && record.exp() > nowEpochSeconds
                    && !record.aud().equals(excluded)) {
                resources.add(record.aud());
            }
        }
        return resources.size();
    }

    @Override
    public synchronized void purgeExpired(long cutoffEpochSeconds) {
        Set<String> gone = new HashSet<>();
        issued.values().removeIf(record -> record.exp() <= cutoffEpochSeconds && gone.add(record.jti()));
        presentations.keySet().removeAll(gone);
        upstreams.keySet().removeAll(gone);
    }
}
