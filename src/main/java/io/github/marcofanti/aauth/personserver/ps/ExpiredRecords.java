package io.github.marcofanti.aauth.personserver.ps;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

/**
 * When a store drops records past their {@code exp} (§11.12.4: entries may be discarded after
 * {@code exp}). Records are kept {@link #GRACE_SECONDS} beyond {@code exp} so a token still
 * accepted within the clock-skew window stays revocable, and a store purges at most once per
 * {@link #INTERVAL_SECONDS}, on a write.
 */
public final class ExpiredRecords {

    public static final long GRACE_SECONDS = 300;
    public static final long INTERVAL_SECONDS = 60;

    private final AtomicLong nextPurge = new AtomicLong();

    /** The purge cutoff if a purge is due now, else {@code -1}; records with {@code exp <= cutoff} go. */
    public long cutoffIfDue() {
        long now = Instant.now().getEpochSecond();
        long next = nextPurge.get();
        if (now < next || !nextPurge.compareAndSet(next, now + INTERVAL_SECONDS)) {
            return -1;
        }
        return now - GRACE_SECONDS;
    }
}
