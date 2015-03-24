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
package wsattacker.sso.openid.attacker.log;

import java.util.ArrayList;
import java.util.List;
import org.jdesktop.observablecollections.ObservableCollections;
import org.jdesktop.observablecollections.ObservableList;
import wsattacker.sso.openid.attacker.server.IdpType;

/**
 * This class is somehow an advanced Logger for OpenID messages.
 * The HTTP Handler will use it to log the order of incoming requests.
 */
final public class RequestLogger {

    final private static RequestLogger INSTANCE = new RequestLogger();
    private final ObservableList<RequestLogEntry> entryList = ObservableCollections.observableList(new ArrayList<RequestLogEntry>());

    public static RequestLogger getInstance() {
        return INSTANCE;
    }

    private RequestLogger() {
    }

    /**
     * Get all entries.
     *
     * @return
     */
    public List<RequestLogEntry> getEntryList() {
        return entryList;
    }

    /**
     * Add a new Entry
     *
     * @param type     The type of the request can be XRDS, Association, Valid
     *                 Token
     *                 or attack token.
     * @param text     A short description
     * @param request  The important part of the HTTP request
     * @param response The important part of the HTTP response
     * @param idpType  Type of IdP: Attacker or Analyzer
     */
    public void add(RequestType type, String text, String request, String response, IdpType idpType) {
        entryList.add(0, new RequestLogEntry(type, text, request, response, idpType));
    }

    /**
     * Clear the log. This will remove all entries.
     */
    public void clear() {
        entryList.clear();
    }
}
