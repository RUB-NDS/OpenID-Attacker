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
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.MessageException;
import org.openid4java.message.ParameterList;

public class UnvalidatedAuthSuccess extends AuthSuccess {

    private static final Log LOG = LogFactory.getLog(UnvalidatedAuthSuccess.class);
    private static final boolean DEBUG = LOG.isDebugEnabled();

    protected UnvalidatedAuthSuccess(ParameterList params) {
        super(params);
    }

    public static AuthSuccess createAuthSuccess(ParameterList params)
      throws MessageException {
        AuthSuccess resp = new UnvalidatedAuthSuccess(params);

        // The response token must not be validated
        // This allows e.g. to create signed tokens WITHOUT claimed_id etc.
        // resp.validate();
        if (DEBUG) {
            LOG.debug("Created positive auth response:\n"
              + resp.keyValueFormEncoding());
        }

        return resp;
    }
}
