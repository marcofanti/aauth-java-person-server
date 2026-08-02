package io.github.marcofanti.aauth.personserver.agentserver;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Caches (key thumbprint, created) pairs to reject replayed HTTP signatures. Best-effort:
 * the aauth library already enforces the 60 s created window; this catches exact duplicates.
 * Always in-process — never persisted (DATABASE.md).
 */
public final class ReplayCache {

    private final long windowSeconds;
    private final Map<String, Long> seen = new LinkedHashMap<>();

    public ReplayCache(long windowSeconds) {
        this.windowSeconds = windowSeconds;
    }

    /** Throws {@link ReplayException} if (thumbprint, created) was seen; otherwise records it. */
    public synchronized void checkAndRecord(String thumbprint, long createdTs) {
        purgeStale();
        String key = thumbprint + "|" + createdTs;
        if (seen.containsKey(key)) {
            throw new ReplayException();
        }
        seen.put(key, System.nanoTime());
    }

    private void purgeStale() {
        long cutoff = System.nanoTime() - (windowSeconds + 5) * 1_000_000_000L;
        Iterator<Map.Entry<String, Long>> iterator = seen.entrySet().iterator();
        while (iterator.hasNext()) {
            if (iterator.next().getValue() < cutoff) {
                iterator.remove();
            }
        }
    }
}
