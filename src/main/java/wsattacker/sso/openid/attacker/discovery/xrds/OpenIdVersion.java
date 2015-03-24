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
package wsattacker.sso.openid.attacker.discovery.xrds;

public enum OpenIdVersion {

    VERSION_10("OpenID v1.0", "http://openid.net/signon/1.0", "http://openid.net/signon/1.0"),
    VERSION_11("OpenID v1.1", "http://openid.net/signon/1.1", "http://openid.net/signon/1.1"),
    VERSION_20_OP_IDENTIFIER_ELEMENT("OpenID v2.0 - OP Identifier Element", "http://specs.openid.net/auth/2.0/server", "http://specs.openid.net/auth/2.0"),
    VERSION_20_CLAIMED_IDENTIFIER_ELEMENT("OpenID v2.0 - Claimed Identifier Element", "http://specs.openid.net/auth/2.0/signon", "http://specs.openid.net/auth/2.0");
    private final String representation, URI, NS;

    private OpenIdVersion(String representation, String URI, String NS) {
        this.representation = representation;
        this.URI = URI;
        this.NS = NS;
    }

    public String getURI() {
        return this.URI;
    }

    public String getNS() {
        return this.NS;
    }

    @Override
    public String toString() {
        return representation;
    }
}
