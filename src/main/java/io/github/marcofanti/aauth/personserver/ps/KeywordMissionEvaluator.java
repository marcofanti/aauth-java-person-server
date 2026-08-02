package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionLogEntry;
import java.net.URI;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic keyword-based mission evaluator (Layer 1 default).
 *
 * <p>Decision policy: explicit deny tokens in the mission description
 * ({@code deny:delete}, {@code never:write}) matching the scope or issuer → deny; scope
 * overlap with approved tools or description keywords → allow; issuer host known to the
 * mission but no scope overlap → clarify; otherwise escalate to user consent.
 *
 * <p>Intentionally simple — it demonstrates the architecture with crisp, predictable
 * outcomes. Production deployments would use an LLM-backed evaluator or a policy engine.
 */
public final class KeywordMissionEvaluator implements MissionEvaluator {

    private static final Pattern TOKEN_RE = Pattern.compile("[a-z0-9][a-z0-9_-]{1,}", Pattern.CASE_INSENSITIVE);
    private static final Pattern DENY_RE = Pattern.compile(
            "\\b(?:deny|never|do\\s+not|forbid)\\s*[:\\-]?\\s*([a-z0-9_:.-]+)", Pattern.CASE_INSENSITIVE);

    private static Set<String> tokens(String text) {
        Set<String> out = new HashSet<>();
        if (text == null || text.isEmpty()) {
            return out;
        }
        Matcher matcher = TOKEN_RE.matcher(text);
        while (matcher.find()) {
            out.add(matcher.group().toLowerCase(Locale.ROOT));
        }
        return out;
    }

    private static Set<String> scopeTokens(String scope) {
        Set<String> out = new HashSet<>();
        if (scope == null || scope.isEmpty()) {
            return out;
        }
        for (String part : scope.strip().split("\\s+")) {
            String lower = part.toLowerCase(Locale.ROOT);
            out.add(lower);
            int colon = lower.indexOf(':');
            if (colon >= 0) {
                out.add(lower.substring(colon + 1));
            }
        }
        return out;
    }

    private static String host(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        try {
            String h = URI.create(url).getHost();
            return h == null ? null : h.toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static Set<String> intersection(Set<String> a, Set<String> b) {
        Set<String> out = new HashSet<>(a);
        out.retainAll(b);
        return out;
    }

    @Override
    public EvaluationDecision evaluate(Mission mission, List<MissionLogEntry> log, TokenRequestSummary request) {
        String desc = mission.description() == null ? "" : mission.description();
        Set<String> descTokens = tokens(desc);
        Set<String> scopeTokens = scopeTokens(request.resourceScope());
        String host = host(request.resourceIss());

        Matcher deny = DENY_RE.matcher(desc);
        while (deny.find()) {
            String forbidden = stripPunctuation(deny.group(1).toLowerCase(Locale.ROOT));
            if (forbidden.isEmpty()) {
                continue;
            }
            if (scopeTokens.contains(forbidden)) {
                return EvaluationDecision.deny("mission explicitly forbids '" + forbidden + "' (matched scope)");
            }
            if (host != null
                    && (forbidden.equals(host) || Set.of(host.split("\\.")).contains(forbidden))) {
                return EvaluationDecision.deny(
                        "mission explicitly forbids '" + forbidden + "' (matched resource host)");
            }
        }

        Set<String> approvedToolNames = new HashSet<>();
        if (mission.approvedTools() != null) {
            for (Map<String, String> tool : mission.approvedTools()) {
                String name = tool.get("name");
                if (name != null && !name.isEmpty()) {
                    approvedToolNames.add(name.toLowerCase(Locale.ROOT));
                }
            }
        }

        Set<String> toolHits = intersection(scopeTokens, approvedToolNames);
        if (!toolHits.isEmpty()) {
            return EvaluationDecision.allow(
                    "requested scope '" + toolHits.iterator().next() + "' matches an approved tool");
        }
        Set<String> descHits = intersection(scopeTokens, descTokens);
        if (!descHits.isEmpty()) {
            return EvaluationDecision.allow(
                    "requested scope '" + descHits.iterator().next() + "' appears in the mission description");
        }

        Set<String> hostLabels = host == null ? Set.of() : Set.of(host.split("\\."));
        if (!intersection(new HashSet<>(hostLabels), descTokens).isEmpty()) {
            String scopeText = request.resourceScope() == null ? "(none)" : request.resourceScope();
            return EvaluationDecision.clarify(
                    "The mission mentions " + host + " but the requested scope '" + scopeText
                            + "' is not obviously in bounds. Clarify how this call advances the mission.",
                    "host known, scope unclear");
        }

        String resource = host != null ? host : (request.resourceIss() != null ? request.resourceIss() : "unknown");
        String scopeText = request.resourceScope() == null ? "(none)" : request.resourceScope();
        return EvaluationDecision.escalate(
                "no overlap between mission scope and request (resource=" + resource + ", scope=" + scopeText + ")");
    }

    private static String stripPunctuation(String value) {
        String out = value;
        while (!out.isEmpty() && ".:-_".indexOf(out.charAt(out.length() - 1)) >= 0) {
            out = out.substring(0, out.length() - 1);
        }
        return out;
    }
}
