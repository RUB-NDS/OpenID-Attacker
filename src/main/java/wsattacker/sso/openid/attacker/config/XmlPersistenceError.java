/*
 * OpenID Attacker
 * (C) 2015 Christian Mainka & Christian Koßmann
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package wsattacker.sso.openid.attacker.config;

import org.apache.log4j.Logger;

/**
 * Exception which will be thrown in the error case when loading or saving
 * a config XML file.
 */
public class XmlPersistenceError extends Exception {

    private static final Logger LOG = Logger.getLogger(XmlPersistenceError.class);

    public XmlPersistenceError(String message) {
        super(message);
        LOG.warn(message);
    }

    public XmlPersistenceError(String message, Throwable cause) {
        super(message, cause);
        LOG.warn(message);
    }

    public XmlPersistenceError(Throwable cause) {
        super(cause);
        LOG.warn(cause);
    }
}
