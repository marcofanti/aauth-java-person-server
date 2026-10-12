package io.github.marcofanti.aauth.personserver.ps.web;

import io.github.marcofanti.aauth.personserver.model.AgentInteractionRequest;
import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionRef;
import io.github.marcofanti.aauth.personserver.model.ToolSpec;
import io.github.marcofanti.aauth.personserver.ps.Draft11MissionStatus;
import io.github.marcofanti.aauth.personserver.ps.Draft11Missions;
import io.github.marcofanti.aauth.personserver.ps.MissionUtils;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.web.HttpSigAuth.SignedRequest;
import io.github.marcofanti.aauth.personserver.web.AAuthResponses;
import io.github.marcofanti.aauth.personserver.web.BodyReader;
import io.github.marcofanti.aauth.personserver.web.BodyValidationException;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import io.github.marcofanti.aauth.personserver.web.RequestExtract;
import io.github.marcofanti.aauth.personserver.web.Sanitize;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Draft-11 {@code mission_endpoint} (§8): {@code POST /agent-missions} proposes a mission and
 * {@code POST /agent-missions/{mission_s256}} acts on one ({@code update}, {@code completion}).
 * Draft-10 agents keep using {@code POST /mission}.
 */
@Profile({"default", "portal", "ps"})
@RestController
public class PsMissionController {

    private final PsContainer ps;
    private final PsAuth auth;
    private final Draft11Missions missions;
    private final Draft11MissionStatus status;
    private final String psOrigin;

    public PsMissionController(PsContainer ps, PsAuth auth, PsSettings settings) {
        this.ps = ps;
        this.auth = auth;
        this.psOrigin = MissionUtils.stripTrailingSlash(settings.origin());
        this.missions = new Draft11Missions(
                ps.mission(), ps.personTokenIssuer(), psOrigin, settings.userId(), settings.missionLifetimeSeconds());
        this.status = new Draft11MissionStatus(ps.mission());
    }

    @PostMapping("/agent-missions")
    public ResponseEntity<Object> propose(HttpServletRequest request, @RequestBody(required = false) byte[] raw) {
        SignedRequest signed = RequestExtract.signedRequest(request, raw);
        PsAuth.TokenAgentContext agent = auth.requireTokenAgent(signed);
        BodyCoverage.require(signed);
        BodyReader body = parse(raw);
        Draft11Missions.Proposal proposal = new Draft11Missions.Proposal(
                Sanitize.markdownOrNull(body.optString("description")),
                tools(body.optList("tools")),
                strings(body.optList("resources")));
        return ResponseEntity.ok(missions.create(agent, proposal).body());
    }

    @PostMapping("/agent-missions/{s256}")
    public ResponseEntity<Object> act(
            HttpServletRequest request, @PathVariable("s256") String s256, @RequestBody(required = false) byte[] raw) {
        SignedRequest signed = RequestExtract.signedRequest(request, raw);
        String agentId = auth.requireTokenAgent(signed).agentId();
        BodyCoverage.require(signed);
        Mission mission = status.requireOwnActive(s256, agentId);
        BodyReader body = parse(raw);
        String action = body.optString("action");
        if ("update".equals(action)) {
            String updateS256 = missions.update(mission, Sanitize.markdownOrNull(body.optString("description")));
            return ResponseEntity.ok(Map.of("s256", updateS256));
        }
        if ("completion".equals(action)) {
            String summary = Sanitize.markdownOrNull(body.optString("summary"));
            if (summary == null || summary.isBlank()) {
                throw new ProblemError(400, "invalid_request", "completion requires a summary");
            }
            AgentInteractionRequest completion = new AgentInteractionRequest(
                    "completion", null, null, null, null, summary, new MissionRef(psOrigin, mission.s256()), agentId);
            return AAuthResponses.jsonDeferred(ps.governance().postAgentInteraction(completion));
        }
        throw new ProblemError(400, "invalid_request", "action must be update or completion");
    }

    private static BodyReader parse(byte[] raw) {
        try {
            return BodyReader.parse(raw);
        } catch (BodyValidationException e) {
            throw new ProblemError(400, "invalid_request", e.getMessage());
        }
    }

    private static List<ToolSpec> tools(List<Object> raw) {
        List<ToolSpec> out = new ArrayList<>();
        if (raw == null) {
            return out;
        }
        for (Object item : raw) {
            if (!(item instanceof Map<?, ?> tool)
                    || !(tool.get("name") instanceof String name)
                    || !(tool.get("description") instanceof String description)) {
                throw new ProblemError(400, "invalid_request", "tools entries require name and description");
            }
            out.add(new ToolSpec(name, description));
        }
        return out;
    }

    private static List<String> strings(List<Object> raw) {
        List<String> out = new ArrayList<>();
        if (raw == null) {
            return out;
        }
        for (Object item : raw) {
            if (!(item instanceof String value)) {
                throw new ProblemError(400, "invalid_request", "resources must be an array of URLs");
            }
            out.add(value);
        }
        return out;
    }
}
