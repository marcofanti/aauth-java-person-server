package io.github.marcofanti.aauth.personserver.ps.web;

import io.github.marcofanti.aauth.personserver.model.MissionRef;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parse and build the AAuth-Mission header (SPEC §AAuth-Mission Request Header). */
public final class MissionHeader {

    private static final Pattern APPROVER = Pattern.compile("approver=\"([^\"]+)\"");
    private static final Pattern S256 = Pattern.compile("s256=\"([^\"]+)\"");

    private MissionHeader() {}

    public static MissionRef parseAAuthMissionHeader(String headerValue) {
        if (headerValue == null || headerValue.isEmpty()) {
            return null;
        }
        Matcher approver = APPROVER.matcher(headerValue);
        Matcher s256 = S256.matcher(headerValue);
        if (!approver.find() || !s256.find()) {
            return null;
        }
        return new MissionRef(approver.group(1), s256.group(1));
    }

    public static String buildAAuthMissionResponseHeader(String approver, String s256) {
        return "approver=\"" + approver + "\"; s256=\"" + s256 + "\"";
    }
}
