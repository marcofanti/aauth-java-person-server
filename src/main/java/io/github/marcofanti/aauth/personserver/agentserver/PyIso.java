package io.github.marcofanti.aauth.personserver.agentserver;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/** Format instants like Python's tz-aware {@code datetime.isoformat()} ({@code +00:00} suffix). */
public final class PyIso {

    private static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSSxxx").withZone(ZoneOffset.UTC);

    private PyIso() {}

    public static String format(Instant instant) {
        return FORMAT.format(instant);
    }
}
