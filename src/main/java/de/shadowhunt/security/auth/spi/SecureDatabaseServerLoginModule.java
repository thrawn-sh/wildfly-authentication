/**
 * Copyright (C) 2016 shadowhunt (dev@shadowhunt.de)
 *
 * This file is part of Shadowhunt Wildfly Authentication.
 *
 * Shadowhunt Wildfly Authentication is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shadowhunt Wildfly Authentication is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Shadowhunt Wildfly Authentication. If not, see http://www.gnu.org/licenses/ .
 */
package de.shadowhunt.security.auth.spi;

import org.jboss.security.auth.spi.DatabaseServerLoginModule;

public class SecureDatabaseServerLoginModule extends DatabaseServerLoginModule {

    @Override
    protected boolean validatePassword(final String suppliedPassword, final String expectedPassword) {
        try {
            final Password expected = Password.parse(expectedPassword);
            return expected.matches(suppliedPassword.toCharArray());
        } catch (final RuntimeException e) {
            setValidateError(e);
            return false;
        }
    }
}
