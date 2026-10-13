package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.PersonTokenRequest;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.tokens.PersonTokens;
import java.time.Instant;

/**
 * Mints draft-11 person tokens (§7.1.2) and records each issuance (§7.1 Retention). Shared by
 * immediate issuance and by consent approval of a deferred request.
 */
public final class PersonTokenIssuer {

    static final long MAX_LIFETIME_SECONDS = 3600;

    /** The issued token and its remaining lifetime, as the endpoint returns it. */
    public record Issued(String personToken, long expiresIn) {}

    private final String iss;
    private final PsSigningService signing;
    private final DirectedSubjects subjects;
    private final PersonTokenLedger ledger;

    public PersonTokenIssuer(
            String psOrigin, PsSigningService signing, DirectedSubjects subjects, PersonTokenLedger ledger) {
        this.iss = MissionUtils.stripTrailingSlash(psOrigin);
        this.signing = signing;
        this.subjects = subjects;
        this.ledger = ledger;
    }

    /** Whether {@code person} has already approved agents acting as them at {@code resource}. */
    public boolean isApproved(String person, String resource) {
        return ledger.isApproved(person, resource);
    }

    /** Record the person's first-use approval for the resource, then issue (§7.1). */
    public Issued approveAndIssue(PersonTokenRequest request, String person) {
        ledger.approve(person, request.resource());
        return issue(request, person);
    }

    /** Live distinct resources {@code agentId} holds person tokens for (rate limiting, §7.1). */
    public int distinctLiveResources(String agentId, String exclude) {
        return ledger.distinctLiveResources(agentId, exclude, Instant.now().getEpochSecond());
    }

    /** The directed {@code sub} this PS uses for {@code person} at {@code resource} (§14.1). */
    public String subFor(String person, String resource) {
        return subjects.subFor(person, resource);
    }

    /**
     * Issue for {@code person}. {@code exp} is at most one hour and never later than
     * {@code request.maxExp()} (agent token, upstream token, or mission expiry). The token carries
     * no {@code scope} or {@code account} (§7.1.2).
     */
    public Issued issue(PersonTokenRequest request, String person) {
        long now = Instant.now().getEpochSecond();
        long exp = now + MAX_LIFETIME_SECONDS;
        if (request.maxExp() != null) {
            exp = Math.min(exp, request.maxExp());
        }
        if (exp <= now) {
            throw new ProblemError(
                    400,
                    "invalid_request",
                    "cannot issue a person token: the agent token or mission has already expired");
        }
        String sub = subjects.subFor(person, request.resource());
        // exp already folds in the agent token, mission and upstream bounds (maxExp), so it is
        // also the bound the library asks for each of them.
        PersonTokens.Spec.Builder spec = PersonTokens.Spec.builder(
                        iss,
                        MissionUtils.stripTrailingSlash(request.resource()),
                        sub,
                        request.cnfJwk(),
                        signing.keyPair().getPrivate(),
                        signing.kid())
                .agentExp(exp)
                .exp(exp);
        if (request.missionS256() != null) {
            spec.mission(request.missionS256(), exp);
        }
        if (request.tenant() != null) {
            spec.tenant(request.tenant());
        }
        String token = PersonTokens.create(spec.build());
        String jti = Jwts.parse(token).claim("jti");
        ledger.recordIssued(new PersonTokenLedger.Issued(
                jti, request.agentId(), person, MissionUtils.stripTrailingSlash(request.resource()), sub, exp));
        if (request.upstream() != null) {
            ledger.recordUpstream(
                    jti, request.upstream().iss(), request.upstream().jti());
        }
        return new Issued(token, exp - now);
    }
}
