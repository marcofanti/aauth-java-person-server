package io.github.marcofanti.aauth.personserver.ps;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DirectedSubjectsTest {

    @Test
    void subIsStablePerPersonAndResource() {
        DirectedSubjects subjects = DirectedSubjects.ephemeral();
        String first = subjects.subFor("alice", "https://rs.example");
        assertThat(subjects.subFor("alice", "https://rs.example")).isEqualTo(first);
        assertThat(subjects.subFor("alice", "https://rs.example/")).isEqualTo(first);
    }

    @Test
    void subDiffersAcrossResourcesAndPersons() {
        DirectedSubjects subjects = DirectedSubjects.ephemeral();
        String atA = subjects.subFor("alice", "https://a.example");
        assertThat(subjects.subFor("alice", "https://b.example")).isNotEqualTo(atA);
        assertThat(subjects.subFor("bob", "https://a.example")).isNotEqualTo(atA);
    }

    @Test
    void separatorPreventsBoundaryCollisions() {
        DirectedSubjects subjects = DirectedSubjects.ephemeral();
        assertThat(subjects.subFor("ab", "c")).isNotEqualTo(subjects.subFor("a", "bc"));
    }

    @Test
    void persistentSecretSurvivesReload(@TempDir Path dir) {
        Path secret = dir.resolve("nested/subjects.secret");
        String sub = DirectedSubjects.persistent(secret).subFor("alice", "https://rs.example");
        assertThat(secret).exists();
        assertThat(DirectedSubjects.persistent(secret).subFor("alice", "https://rs.example"))
                .isEqualTo(sub);
    }

    @Test
    void corruptSecretFailsWithActionableMessage(@TempDir Path dir) throws Exception {
        Path secret = dir.resolve("subjects.secret");
        Files.writeString(secret, "c2hvcnQ=", StandardCharsets.UTF_8);
        assertThatThrownBy(() -> DirectedSubjects.persistent(secret))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("delete it to regenerate");
    }

    @Test
    void missingInputsAreRejected() {
        DirectedSubjects subjects = DirectedSubjects.ephemeral();
        assertThatThrownBy(() -> subjects.subFor(null, "https://rs.example")).isNotNull();
        assertThatThrownBy(() -> subjects.subFor("alice", null)).isNotNull();
    }
}
