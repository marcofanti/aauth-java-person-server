package io.github.marcofanti.aauth.personserver.ps.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.model.AuthTokenResponse;
import io.github.marcofanti.aauth.personserver.model.PersonTokenRequest;
import io.github.marcofanti.aauth.personserver.ps.AuthTokenIssuer;
import io.github.marcofanti.aauth.personserver.ps.FakeAccessServer;
import io.github.marcofanti.aauth.personserver.ps.FakeAgentProvider;
import io.github.marcofanti.aauth.personserver.ps.PersonTokenLedger;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.PsWiring;
import io.github.marcofanti.aauth.personserver.ps.TrustedAgentServer;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.RequestSigner;
import io.github.marcofanti.aauth.signing.SignRequest;
import io.github.marcofanti.aauth.signing.SignatureScheme;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import io.github.marcofanti.aauth.tokens.AgentTokens;
import io.github.marcofanti.aauth.tokens.AuthTokens;
import io.github.marcofanti.aauth.tokens.PersonTokens;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Call chaining (§10.1.1, §9.4.5): an intermediary that is its own agent provider obtains a
 * person token and an auth token for a downstream resource, presenting the calling agent's token
 * as {@code upstream_token}.
 */
@SpringBootTest(properties = "spring.main.allow-bean-definition-overriding=true")
@AutoConfigureMockMvc
class PsCallChainingHttpTest {

    private static final String PS_ORIGIN = "http://localhost";
    private static final List<String> BODY_COMPONENTS = List.of("content-type", "content-digest");
    // MockMvc rewrites a bare application/json to this; sign the value it actually sends.
    private static final String JSON_UTF8 = "application/json;charset=UTF-8";
    private static final String DOWNSTREAM = "https://downstream.example";
    private static final String CALLER_ID = "aauth:planner.7f3c@agent-server.example";
    private static final String INTERMEDIARY_ID = "aauth:chain@127.0.0.1";

    private static final KeyPair CALLER_KEY = KeyPairs.generateEd25519();
    private static final KeyPair INTERMEDIARY_KEY = KeyPairs.generateEd25519();
    private static final KeyPair AP_KEY = KeyPairs.generateEd25519();
    private static final KeyPair RS_KEY = KeyPairs.generateEd25519();
    private static final FakeAgentProvider INTERMEDIARY = new FakeAgentProvider();
    private static final FakeAccessServer ACCESS_SERVER = new FakeAccessServer();

    private static Map<String, Object> jwk(KeyPair keyPair) {
        return new LinkedHashMap<>(Jwk.publicKeyToJwk(keyPair.getPublic(), "eph"));
    }

    @TestConfiguration
    static class Config {
        @Bean
        PsSettings psSettings() {
            return new PsSettings(
                    PS_ORIGIN,
                    false,
                    null,
                    null,
                    "user",
                    false,
                    true,
                    null,
                    "stub-agent-jwt",
                    600,
                    null,
                    null,
                    3600,
                    null,
                    null,
                    null,
                    null);
        }

        @Bean
        PsContainer psContainer(PsSettings settings) {
            return PsWiring.buildMemoryPs(PsWiring.Options.builder(settings.origin())
                    .insecureDev(false)
                    .signingKeyPath(null)
                    .trustFile(null)
                    .consentScopesFile(null)
                    .selfJwksProvider(() -> Map.of("keys", List.of(Jwk.publicKeyToJwk(AP_KEY.getPublic(), "ap-kid"))))
                    .resourceJwks(iss -> DOWNSTREAM.equals(iss.replaceAll("/+$", ""))
                            ? Map.of("keys", List.of(Jwk.publicKeyToJwk(RS_KEY.getPublic(), "rs-kid")))
                            : null)
                    .build());
        }
    }

    @AfterAll
    static void stopServers() {
        INTERMEDIARY.close();
        ACCESS_SERVER.close();
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private PsContainer ps;

    @BeforeEach
    void trustTheIntermediaryAndApproveTheDownstreamResource() {
        if (!ps.trustRegistry().isTrusted(INTERMEDIARY.origin())) {
            ps.trustRegistry()
                    .add(new TrustedAgentServer(
                            INTERMEDIARY.origin(), "intermediary", INTERMEDIARY.origin() + "/jwks", "", null));
        }
        ps.personTokenLedger().approve("user", DOWNSTREAM);
    }

    private static long inOneHour() {
        return Instant.now().getEpochSecond() + 3600;
    }

    /** The token the calling agent presented to the intermediary: a person token whose aud is it. */
    private String upstreamPersonToken(String missionS256, Long maxExp) {
        return upstreamPersonToken(CALLER_ID, missionS256, maxExp);
    }

    private String upstreamPersonToken(String callerId, String missionS256, Long maxExp) {
        return ps.personTokenIssuer()
                .issue(
                        new PersonTokenRequest(
                                callerId,
                                jwk(CALLER_KEY),
                                INTERMEDIARY.origin(),
                                missionS256,
                                null,
                                maxExp != null ? maxExp : inOneHour(),
                                null,
                                null,
                                null,
                                null,
                                null),
                        "user")
                .personToken();
    }

    private MvcResult intermediaryPost(String path, Map<String, Object> params) throws Exception {
        return signedPost(
                path,
                params,
                INTERMEDIARY_KEY,
                INTERMEDIARY.agentToken(INTERMEDIARY_ID, INTERMEDIARY_KEY, inOneHour()));
    }

    private MvcResult signedPost(String path, Map<String, Object> params, KeyPair key, String agentToken)
            throws Exception {
        byte[] body = Json.write(params).getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = RequestSigner.sign(SignRequest.builder("POST", PS_ORIGIN + path)
                .headers(Map.of("Host", "localhost", "Content-Type", JSON_UTF8))
                .body(body)
                .keyPair(key)
                .scheme(new SignatureScheme.Jwt(agentToken))
                .additionalComponents(BODY_COMPONENTS)
                .build());
        var request = post(path).contentType(JSON_UTF8).content(body);
        headers.forEach(request::header);
        return mvc.perform(request).andReturn();
    }

    private MvcResult downstreamPersonToken(String upstream) throws Exception {
        return intermediaryPost("/person-token", Map.of("resource", DOWNSTREAM, "upstream_token", upstream));
    }

    /** What the downstream resource issues after seeing the intermediary's person token. */
    private static String downstreamResourceToken(String presented, String scope) {
        Map<String, Object> claims = Jwts.parse(presented).payload();
        return ResourceTokens.create(new ResourceTokens.Spec(
                DOWNSTREAM,
                PS_ORIGIN,
                Jwk.thumbprint(jwk(INTERMEDIARY_KEY)),
                scope,
                PS_ORIGIN,
                String.valueOf(claims.get("sub")),
                String.valueOf(claims.get("jti")),
                RS_KEY.getPrivate(),
                "rs-kid",
                inOneHour(),
                (String) claims.get("mission_s256"),
                null,
                null,
                null));
    }

    private static Map<String, Object> json(MvcResult result) throws Exception {
        return Json.readMap(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private static void assertProblem(MvcResult result, int status, String error) throws Exception {
        assertThat(result.getResponse().getStatus()).isEqualTo(status);
        assertThat(json(result)).containsEntry("error", error);
    }

    private String proposeMissionAsCaller() throws Exception {
        String callerToken = AgentTokens.create(
                AgentTokens.Spec.builder(PS_ORIGIN, CALLER_ID, jwk(CALLER_KEY), AP_KEY.getPrivate(), "ap-kid")
                        .exp(inOneHour())
                        .build());
        MvcResult created = signedPost(
                "/agent-missions",
                Map.of(
                        "description",
                        "Book a trip",
                        "tools",
                        List.of(Map.of("name", "book", "description", "Book travel"))),
                CALLER_KEY,
                callerToken);
        assertThat(created.getResponse().getStatus()).isEqualTo(200);
        return (String) json(created).get("s256");
    }

    @Test
    void theDownstreamPersonTokenIsForTheUpstreamPersonAndCarriesItsMission() throws Exception {
        String s256 = proposeMissionAsCaller();
        String upstream = upstreamPersonToken(s256, null);

        MvcResult result = downstreamPersonToken(upstream);

        assertThat(result.getResponse().getStatus())
                .as(result.getResponse().getContentAsString())
                .isEqualTo(200);
        Jwts.Decoded token = Jwts.parse((String) json(result).get("person_token"));
        assertThat(token.claim("aud")).isEqualTo(DOWNSTREAM);
        assertThat(token.claim("sub"))
                .isEqualTo(ps.personTokenIssuer().subFor("user", DOWNSTREAM))
                .isNotEqualTo(Jwts.parse(upstream).claim("sub"));
        assertThat(token.claim("mission_s256")).isEqualTo(s256);
        assertThat(token.numericClaim("exp"))
                .isLessThanOrEqualTo(Jwts.parse(upstream).numericClaim("exp"));
        @SuppressWarnings("unchecked")
        Map<String, Object> cnf = (Map<String, Object>) token.payload().get("cnf");
        assertThat(Jwk.thumbprint(castJwk(cnf.get("jwk")))).isEqualTo(Jwk.thumbprint(jwk(INTERMEDIARY_KEY)));
        assertThat(ps.personTokenLedger()
                        .issuedFromUpstream(PS_ORIGIN, Jwts.parse(upstream).claim("jti")))
                .extracting(PersonTokenLedger.Issued::jti)
                .containsExactly(token.claim("jti"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castJwk(Object jwk) {
        return (Map<String, Object>) jwk;
    }

    @Test
    void anIntermediarySendsNoMissionOrSubagentOfItsOwn() throws Exception {
        String upstream = upstreamPersonToken(null, null);
        Map<String, Object> withMission = new HashMap<>(Map.of("resource", DOWNSTREAM, "upstream_token", upstream));
        withMission.put("mission_s256", "A".repeat(43));
        assertProblem(intermediaryPost("/person-token", withMission), 400, "invalid_request");
    }

    @Test
    void anUpstreamTokenForAnotherAudienceIsInvalid() throws Exception {
        String forSomeoneElse = ps.personTokenIssuer()
                .issue(
                        new PersonTokenRequest(
                                CALLER_ID,
                                jwk(CALLER_KEY),
                                "https://elsewhere.example",
                                null,
                                null,
                                inOneHour(),
                                null,
                                null,
                                null,
                                null,
                                null),
                        "user")
                .personToken();
        assertProblem(downstreamPersonToken(forSomeoneElse), 400, ProblemError.INVALID_UPSTREAM_TOKEN);
    }

    @Test
    void onlyPersonAndAuthTokensAreUpstreamTokens() throws Exception {
        String agentToken = INTERMEDIARY.agentToken(CALLER_ID, CALLER_KEY, inOneHour());
        assertProblem(downstreamPersonToken(agentToken), 400, ProblemError.INVALID_UPSTREAM_TOKEN);
    }

    private String signedPersonToken(long exp) {
        return PersonTokens.create(new PersonTokens.Spec(
                PS_ORIGIN,
                "sub-x",
                INTERMEDIARY.origin(),
                jwk(CALLER_KEY),
                ps.psSigning().keyPair().getPrivate(),
                ps.psSigning().kid(),
                exp,
                null,
                null,
                null,
                null,
                null));
    }

    @Test
    void anExpiredUpstreamTokenIsExpired() throws Exception {
        assertProblem(
                downstreamPersonToken(signedPersonToken(Instant.now().getEpochSecond() - 10)),
                400,
                ProblemError.EXPIRED_UPSTREAM_TOKEN);
    }

    @Test
    void anUpstreamTokenThisPsHasNoRecordOfIsInvalid() throws Exception {
        assertProblem(downstreamPersonToken(signedPersonToken(inOneHour())), 400, ProblemError.INVALID_UPSTREAM_TOKEN);
    }

    @Test
    void aRevokedUpstreamTokenIsRevoked() throws Exception {
        String upstream = upstreamPersonToken(null, null);
        ps.revocations().revoke(PS_ORIGIN, Jwts.parse(upstream).claim("jti"), inOneHour());
        assertProblem(downstreamPersonToken(upstream), 400, ProblemError.REVOKED_UPSTREAM_TOKEN);
    }

    @Test
    void anUpstreamTokenFromARevokedCallingAgentIsRevoked() throws Exception {
        String revokedCaller = "aauth:revoked.1@agent-server.example";
        String upstream = upstreamPersonToken(revokedCaller, null, null);
        ps.revocations().recordAgentRevocation(revokedCaller, Instant.now().getEpochSecond());
        assertProblem(downstreamPersonToken(upstream), 400, ProblemError.REVOKED_UPSTREAM_TOKEN);
    }

    @Test
    void theDownstreamAuthTokenIsCappedByTheUpstreamTokenAndKeepsTheDownstreamSub() throws Exception {
        String upstream = upstreamPersonToken(null, Instant.now().getEpochSecond() + 900);
        String person = (String) json(downstreamPersonToken(upstream)).get("person_token");

        MvcResult result = intermediaryPost(
                "/auth-token",
                Map.of(
                        "resource_token", downstreamResourceToken(person, "files.read"),
                        "presented_token", person,
                        "upstream_token", upstream));

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        Jwts.Decoded auth = Jwts.parse((String) json(result).get("auth_token"));
        assertThat(auth.claim("sub")).isEqualTo(Jwts.parse(person).claim("sub"));
        assertThat(auth.numericClaim("exp"))
                .isLessThanOrEqualTo(Jwts.parse(upstream).numericClaim("exp"));
        assertThat(auth.payload()).doesNotContainKey("act");
    }

    @Test
    void anAuthTokenRequestWithAForeignUpstreamTokenIsRejected() throws Exception {
        String upstream = upstreamPersonToken(null, null);
        String person = (String) json(downstreamPersonToken(upstream)).get("person_token");

        MvcResult result = intermediaryPost(
                "/auth-token",
                Map.of(
                        "resource_token", downstreamResourceToken(person, "files.read"),
                        "presented_token", person,
                        "upstream_token", signedPersonToken(inOneHour())));

        assertProblem(result, 400, ProblemError.INVALID_UPSTREAM_TOKEN);
    }

    @Test
    void aDeferredDownstreamRequestEndsWhenTheUpstreamTokenExpires() throws Exception {
        String upstream = upstreamPersonToken(null, Instant.now().getEpochSecond() + 900);
        String person = (String) json(downstreamPersonToken(upstream)).get("person_token");

        MvcResult deferred = intermediaryPost(
                "/auth-token",
                Map.of(
                        "resource_token", downstreamResourceToken(person, "require:user"),
                        "presented_token", person,
                        "upstream_token", upstream));

        assertThat(deferred.getResponse().getStatus()).isEqualTo(202);
        String pendingId = (String) json(deferred).get("pending_id");
        assertThat(ps.pendingStore().getRecord(pendingId).deadline)
                .isEqualTo(Jwts.parse(upstream).numericClaim("exp"));
    }

    @Test
    void anAuthTokenThisPsIssuedIsAnUpstreamToken() throws Exception {
        String person = upstreamPersonToken(null, null);
        Map<String, Object> resourceClaims = new HashMap<>();
        resourceClaims.put("iss", INTERMEDIARY.origin());
        resourceClaims.put("aud", PS_ORIGIN);
        resourceClaims.put("ps", PS_ORIGIN);
        resourceClaims.put("sub", Jwts.parse(person).claim("sub"));
        resourceClaims.put("presented_jti", Jwts.parse(person).claim("jti"));
        resourceClaims.put("scope", "trips.book");
        AuthTokenResponse auth = ps.authIssuer()
                .issue(new AuthTokenIssuer.IssueSpec(
                        CALLER_ID, jwk(CALLER_KEY), resourceClaims, null, null, "autonomous", inOneHour()));

        MvcResult result = downstreamPersonToken(auth.authToken());

        assertThat(result.getResponse().getStatus())
                .as(result.getResponse().getContentAsString())
                .isEqualTo(200);
    }

    private String accessServerAuthToken(String person) {
        return AuthTokens.create(AuthTokens.Spec.builder(
                        ACCESS_SERVER.origin(),
                        INTERMEDIARY.origin(),
                        Jwts.parse(person).claim("sub"),
                        PS_ORIGIN)
                .cnfJwk(jwk(CALLER_KEY))
                .signingKey(ACCESS_SERVER.key().getPrivate(), FakeAccessServer.KID)
                .scope("trips.book")
                .exp(Jwts.parse(person).numericClaim("exp"))
                .dwk("aauth-access.json")
                .build());
    }

    @Test
    void anAuthTokenFromAnAccessServerThePsPresentedToIsAnUpstreamToken() throws Exception {
        String person = upstreamPersonToken(null, null);
        ps.personTokenLedger()
                .recordPresentation(
                        Jwts.parse(person).claim("jti"), ACCESS_SERVER.origin(), Jwk.thumbprint(jwk(CALLER_KEY)));

        MvcResult result = downstreamPersonToken(accessServerAuthToken(person));

        assertThat(result.getResponse().getStatus())
                .as(result.getResponse().getContentAsString())
                .isEqualTo(200);
    }

    @Test
    void anAuthTokenFromAnAccessServerThePsNeverPresentedToIsInvalid() throws Exception {
        // Another person, so no presentation recorded by other tests covers this (aud, sub).
        String person = ps.personTokenIssuer()
                .issue(
                        new PersonTokenRequest(
                                CALLER_ID,
                                jwk(CALLER_KEY),
                                INTERMEDIARY.origin(),
                                null,
                                null,
                                inOneHour(),
                                null,
                                null,
                                null,
                                null,
                                null),
                        "someone-else")
                .personToken();
        assertProblem(downstreamPersonToken(accessServerAuthToken(person)), 400, ProblemError.INVALID_UPSTREAM_TOKEN);
    }

    @Test
    void anUpstreamAuthTokenNamingAnotherPersonServerIsInvalid() throws Exception {
        String person = upstreamPersonToken(null, null);
        ps.personTokenLedger()
                .recordPresentation(
                        Jwts.parse(person).claim("jti"), ACCESS_SERVER.origin(), Jwk.thumbprint(jwk(CALLER_KEY)));
        String foreignPs = AuthTokens.create(AuthTokens.Spec.builder(
                        ACCESS_SERVER.origin(),
                        INTERMEDIARY.origin(),
                        Jwts.parse(person).claim("sub"),
                        "https://other-ps.example")
                .cnfJwk(jwk(CALLER_KEY))
                .signingKey(ACCESS_SERVER.key().getPrivate(), FakeAccessServer.KID)
                .exp(Jwts.parse(person).numericClaim("exp"))
                .dwk("aauth-access.json")
                .build());

        assertProblem(downstreamPersonToken(foreignPs), 400, ProblemError.INVALID_UPSTREAM_TOKEN);
    }

    @Test
    void theAuthTokenNeverOutlivesTheUpstreamTokenOfItsOwnRequest() throws Exception {
        String longUpstream = upstreamPersonToken(null, null);
        String person = (String) json(downstreamPersonToken(longUpstream)).get("person_token");
        String shortUpstream = upstreamPersonToken(null, Instant.now().getEpochSecond() + 600);

        MvcResult result = intermediaryPost(
                "/auth-token",
                Map.of(
                        "resource_token", downstreamResourceToken(person, "files.read"),
                        "presented_token", person,
                        "upstream_token", shortUpstream));

        assertThat(result.getResponse().getStatus())
                .as(result.getResponse().getContentAsString())
                .isEqualTo(200);
        assertThat(Jwts.parse((String) json(result).get("auth_token")).numericClaim("exp"))
                .isLessThanOrEqualTo(Jwts.parse(shortUpstream).numericClaim("exp"));
    }

    @Test
    void anAccessServerTokenResolvesToTheAgentWhoseKeyItBinds() throws Exception {
        // Two agents of the same person share (aud, sub); only the revoked one presented to the AS.
        String revokedCaller = "aauth:revoked.2@agent-server.example";
        KeyPair revokedKey = KeyPairs.generateEd25519();
        String revokedPerson = ps.personTokenIssuer()
                .issue(
                        new PersonTokenRequest(
                                revokedCaller,
                                jwk(revokedKey),
                                INTERMEDIARY.origin(),
                                null,
                                null,
                                inOneHour(),
                                null,
                                null,
                                null,
                                null,
                                null),
                        "user")
                .personToken();
        ps.personTokenLedger()
                .recordPresentation(
                        Jwts.parse(revokedPerson).claim("jti"),
                        ACCESS_SERVER.origin(),
                        Jwk.thumbprint(jwk(revokedKey)));
        String liveCallersToken = upstreamPersonToken(null, Instant.now().getEpochSecond() + 7200);
        ps.personTokenLedger()
                .recordPresentation(
                        Jwts.parse(liveCallersToken).claim("jti"),
                        ACCESS_SERVER.origin(),
                        Jwk.thumbprint(jwk(CALLER_KEY)));
        ps.revocations().recordAgentRevocation(revokedCaller, Instant.now().getEpochSecond() + 5);
        String asToken = AuthTokens.create(AuthTokens.Spec.builder(
                        ACCESS_SERVER.origin(),
                        INTERMEDIARY.origin(),
                        Jwts.parse(revokedPerson).claim("sub"),
                        PS_ORIGIN)
                .cnfJwk(jwk(revokedKey))
                .signingKey(ACCESS_SERVER.key().getPrivate(), FakeAccessServer.KID)
                .exp(Jwts.parse(revokedPerson).numericClaim("exp"))
                .dwk("aauth-access.json")
                .build());

        assertProblem(downstreamPersonToken(asToken), 400, ProblemError.REVOKED_UPSTREAM_TOKEN);
    }
}
