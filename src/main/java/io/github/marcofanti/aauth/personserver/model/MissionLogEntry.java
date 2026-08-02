package io.github.marcofanti.aauth.personserver.model;

import java.time.Instant;
import java.util.Map;

/** Single ordered entry in the mission log. */
public record MissionLogEntry(Instant ts, MissionLogKind kind, Map<String, Object> payload) {}
