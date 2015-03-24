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
package wsattacker.sso.openid.attacker.server.utilities;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.MessageException;
import org.openid4java.message.ParameterList;
import org.openid4java.server.RealmVerifier;

public class UnvalidatedAuthRequest extends AuthRequest {

    private static final Log LOG = LogFactory.getLog(UnvalidatedAuthRequest.class);
    private static final boolean DEBUG = LOG.isDebugEnabled();

    protected UnvalidatedAuthRequest(ParameterList params) {
        super(params);
    }

    public static AuthRequest createAuthRequest(ParameterList params,
      RealmVerifier realmVerifier)
      throws MessageException {
        AuthRequest req = new UnvalidatedAuthRequest(params);

        req.setRealmVerifier(realmVerifier);

        // The request must not be validated
        // req.validate();
        if (DEBUG) {
            LOG.debug("Created auth request:\n" + req.keyValueFormEncoding());
        }

        return req;
    }
}
