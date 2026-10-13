package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.RequirementLevel;
import java.util.List;

/**
 * An access server's 202 (§9.1.2) that the PS passes down to the agent: the AS pending URL the PS
 * keeps polling, and what the agent sees meanwhile. {@code url} and {@code code} are the AS's
 * interaction URL and code for {@code requirement=interaction}; {@code clarification},
 * {@code timeout} and {@code options} carry an AS question for {@code requirement=clarification}.
 */
public record AsPending(
        String pendingUrl,
        RequirementLevel requirement,
        String url,
        String code,
        String clarification,
        Integer timeout,
        List<String> options,
        boolean interacting) {

    public AsPending {
        options = options == null ? null : List.copyOf(options);
    }
}
