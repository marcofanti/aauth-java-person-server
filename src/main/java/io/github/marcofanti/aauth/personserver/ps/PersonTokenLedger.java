package io.github.marcofanti.aauth.personserver.ps;

import java.util.List;

/**
 * Draft-11 person-token bookkeeping: which resources the person has approved (§7.1 first-use
 * consent) and the issuance record each person token requires (§7.1 Retention).
 */
public interface PersonTokenLedger {

    /** One issued person token; kept until {@code exp} plus clock skew (§7.1). */
    record Issued(String jti, String agentId, String person, String aud, String sub, long exp) {}

    boolean isApproved(String person, String resource);

    void approve(String person, String resource);

    void recordIssued(Issued issued);

    Issued findByJti(String jti);

    /** Record that the person token {@code jti} was presented to the AS {@code asIssuer} (§11.12.4). */
    void recordPresentation(String jti, String asIssuer);

    /** The ASes a person token was presented to, which a revocation of it must reach. */
    List<String> presentedTo(String jti);

    /** Record that person token {@code jti} was issued on the upstream token {@code (iss, jti)} (§11.12.4). */
    void recordUpstream(String jti, String upstreamIss, String upstreamJti);

    /** Person tokens issued on the upstream token {@code (iss, jti)}, which its revocation reaches. */
    List<Issued> issuedFromUpstream(String upstreamIss, String upstreamJti);

    /** Person tokens issued for directed identifier {@code sub} at {@code aud} (§9.4.5 step 4). */
    List<Issued> findBySubject(String aud, String sub);

    /** Unexpired person tokens issued to {@code agentId}, for the revocation cascade (§11.12.4). */
    List<Issued> liveFor(String agentId, long nowEpochSeconds);

    /**
     * Distinct resources other than {@code exclude} that {@code agentId} holds unexpired person
     * tokens for, so refreshing an already-held resource never counts against the limit.
     */
    int distinctLiveResources(String agentId, String exclude, long nowEpochSeconds);
}
