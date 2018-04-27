package com.jdriven.stateless.social.connection.repository;

import org.springframework.social.connect.ConnectionFactoryLocator;

/**
 * A short-lived (per request) ConnectionRepository for a single user
 */
public class TemporaryConnectionRepository extends InMemoryConnectionRepository {
    public TemporaryConnectionRepository(ConnectionFactoryLocator connectionFactoryLocator) {
        super(connectionFactoryLocator);
    }
}
