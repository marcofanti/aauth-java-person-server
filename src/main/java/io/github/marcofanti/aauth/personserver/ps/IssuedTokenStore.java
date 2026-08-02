package io.github.marcofanti.aauth.personserver.ps;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Records issued auth tokens for audit. */
public interface IssuedTokenStore {

    record IssuedToken(
            String authToken,
            String agentId,
            String ownerId,
            String resourceIss,
            String resourceScope,
            String justification,
            String issueMethod,
            Instant expiresAt) {}

    /** Persist a record of an issued auth token. */
    void recordIssued(IssuedToken issued);

    /** Return all issued token records, newest first. */
    List<Map<String, Object>> listIssued();
}
