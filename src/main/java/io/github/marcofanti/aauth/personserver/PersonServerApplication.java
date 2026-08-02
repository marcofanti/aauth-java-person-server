package io.github.marcofanti.aauth.personserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;

/**
 * DataSource autoconfiguration is excluded: database mode is driven by
 * {@code AAUTH_DATABASE_URL} (SQLAlchemy-style URL) via {@code DbHolder}, not Spring
 * properties.
 */
@SpringBootApplication(exclude = DataSourceAutoConfiguration.class)
public class PersonServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(PersonServerApplication.class, args);
    }
}
