package io.github.marcofanti.aauth.personserver.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Approved mission: {@code blobBytes} are the exact JSON bytes used for s256.
 *
 * <p>{@code approvedTools} and {@code capabilities} are nullable, matching the Python model
 * where absence and empty are distinct.
 */
public record Mission(
        String s256,
        byte[] blobBytes,
        MissionState state,
        String agentId,
        Instant approvedAt,
        String ownerId,
        String approver,
        String description,
        List<Map<String, String>> approvedTools,
        List<String> capabilities)
        implements MissionOutcome, PendingStoreValue {

    public Mission withState(MissionState newState) {
        return new Mission(
                s256,
                blobBytes,
                newState,
                agentId,
                approvedAt,
                ownerId,
                approver,
                description,
                approvedTools,
                capabilities);
    }
}
