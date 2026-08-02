package io.github.marcofanti.aauth.personserver.model;

/** Mission object in JSON bodies: approver URL + s256 (SPEC). */
public record MissionRef(String approver, String s256) {}
