package io.github.marcofanti.aauth.personserver;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.marcofanti.aauth.personserver.agentserver.AgentServerException;
import io.github.marcofanti.aauth.personserver.agentserver.BindingNotFoundException;
import io.github.marcofanti.aauth.personserver.agentserver.BindingRevokedException;
import io.github.marcofanti.aauth.personserver.agentserver.DuplicateStableKeyException;
import io.github.marcofanti.aauth.personserver.agentserver.InvalidSignatureException;
import io.github.marcofanti.aauth.personserver.agentserver.RegistrationDeniedException;
import io.github.marcofanti.aauth.personserver.agentserver.RegistrationExpiredException;
import io.github.marcofanti.aauth.personserver.agentserver.RegistrationNotFoundException;
import io.github.marcofanti.aauth.personserver.agentserver.ReplayException;
import io.github.marcofanti.aauth.personserver.agentserver.StableKeyAlreadyBoundException;
import io.github.marcofanti.aauth.personserver.ps.AgentTokenRejectException;
import io.github.marcofanti.aauth.personserver.ps.ClarificationLimitException;
import io.github.marcofanti.aauth.personserver.ps.ForbiddenOwnerException;
import io.github.marcofanti.aauth.personserver.ps.InvalidInteractionCodeException;
import io.github.marcofanti.aauth.personserver.ps.MissionDeniedException;
import io.github.marcofanti.aauth.personserver.ps.MissionTerminatedException;
import io.github.marcofanti.aauth.personserver.ps.NotFoundException;
import io.github.marcofanti.aauth.personserver.ps.PendingDeniedException;
import io.github.marcofanti.aauth.personserver.ps.PendingExpiredException;
import io.github.marcofanti.aauth.personserver.ps.PendingGoneException;
import io.github.marcofanti.aauth.personserver.ps.PsException;
import io.github.marcofanti.aauth.personserver.ps.ResourceTokenRejectException;
import io.github.marcofanti.aauth.personserver.ps.SlowDownException;
import org.junit.jupiter.api.Test;

class ExceptionsTest {

    @Test
    void psExceptionsCarryReasonAndErrorFields() {
        assertThat(new PendingDeniedException().reason()).isEqualTo("denied");
        assertThat(new PendingDeniedException("policy").reason()).isEqualTo("policy");
        assertThat(new MissionDeniedException().reason()).isEqualTo("outside mission scope");
        assertThat(new MissionDeniedException("nope").reason()).isEqualTo("nope");
        assertThat(new ResourceTokenRejectException("bad token", "invalid_token").error())
                .isEqualTo("invalid_token");
        assertThat(new AgentTokenRejectException("bad sig", "invalid_signature").error())
                .isEqualTo("invalid_signature");
    }

    @Test
    void psExceptionsShareBase() {
        assertThat(new PendingGoneException()).isInstanceOf(PsException.class);
        assertThat(new NotFoundException()).isInstanceOf(PsException.class);
        assertThat(new ForbiddenOwnerException()).isInstanceOf(PsException.class);
        assertThat(new PendingExpiredException()).isInstanceOf(PsException.class);
        assertThat(new SlowDownException()).isInstanceOf(PsException.class);
        assertThat(new ClarificationLimitException()).isInstanceOf(PsException.class);
        assertThat(new InvalidInteractionCodeException()).isInstanceOf(PsException.class);
        assertThat(new MissionTerminatedException()).isInstanceOf(PsException.class);
    }

    @Test
    void agentServerExceptionsShareBase() {
        assertThat(new BindingNotFoundException()).isInstanceOf(AgentServerException.class);
        assertThat(new BindingRevokedException()).isInstanceOf(AgentServerException.class);
        assertThat(new RegistrationNotFoundException()).isInstanceOf(AgentServerException.class);
        assertThat(new RegistrationExpiredException()).isInstanceOf(AgentServerException.class);
        assertThat(new RegistrationDeniedException()).isInstanceOf(AgentServerException.class);
        assertThat(new InvalidSignatureException("bad")).hasMessage("bad");
        assertThat(new DuplicateStableKeyException()).isInstanceOf(AgentServerException.class);
        assertThat(new ReplayException()).isInstanceOf(AgentServerException.class);
    }

    @Test
    void stableKeyAlreadyBoundCarriesAgentIdInMessage() {
        StableKeyAlreadyBoundException exception = new StableKeyAlreadyBoundException("aauth:x@d");
        assertThat(exception.agentId()).isEqualTo("aauth:x@d");
        assertThat(exception.getMessage()).isEqualTo("This stable key is already bound to active agent aauth:x@d.");
    }
}
