package io.github.marcofanti.aauth.personserver.persistence;

import com.zaxxer.hikari.HikariDataSource;
import javax.sql.DataSource;

/**
 * Optional database handle: present when an {@code AAUTH_*DATABASE_URL} is configured,
 * empty for in-memory mode. Closed on shutdown so connection pools dispose cleanly.
 */
public final class DbHolder implements AutoCloseable {

    private final DataSource dataSource;

    private DbHolder(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public static DbHolder fromUrl(String sqlalchemyUrl) {
        if (sqlalchemyUrl == null || sqlalchemyUrl.isEmpty()) {
            return new DbHolder(null);
        }
        DataSource dataSource = DatabaseUrls.dataSourceFor(sqlalchemyUrl);
        DatabaseUrls.initDb(dataSource);
        return new DbHolder(dataSource);
    }

    public boolean isPresent() {
        return dataSource != null;
    }

    public DataSource dataSource() {
        if (dataSource == null) {
            throw new IllegalStateException("no database configured");
        }
        return dataSource;
    }

    @Override
    public void close() {
        if (dataSource instanceof HikariDataSource hikari) {
            hikari.close();
        }
    }
}
