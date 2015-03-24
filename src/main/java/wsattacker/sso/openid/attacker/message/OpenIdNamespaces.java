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
package wsattacker.sso.openid.attacker.message;

public final class OpenIdNamespaces {

    public static final String AX_NICKNAME = "http://axschema.org/namePerson/friendly";
    public static final String AX_EMAIL = "http://axschema.org/contact/email";
    public static final String AX_FULLNAME = "http://axschema.org/namePerson";
    public static final String AX_DOB = "http://axschema.org/birthDate";
    public static final String AX_GENDER = "http://axschema.org/person/gender";
    public static final String AX_POSTCODE = "http://axschema.org/contact/postalCode/home";
    public static final String AX_COUNTRY = "http://axschema.org/contact/country/home";
    public static final String AX_LANGUAGE = "http://axschema.org/pref/language";
    public static final String AX_TIMEZONE = "http://axschema.org/pref/timezone";
    public static final String OPENID_NICKNAME = "http://openid.net/schema/namePerson/friendly";
    public static final String OPENID_EMAIL = "http://openid.net/schema/contact/internet/email";
    public static final String OPENID_GENDER = "http://openid.net/schema/gender";
    public static final String OPENID_POSTCODE = "http://openid.net/schema/contact/postalCode/home";
    public static final String OPENID_COUNTRY = "http://openid.net/schema/contact/country/home";
    public static final String OPENID_LANGUAGE = "http://openid.net/schema/language/pref";
    public static final String OPENID_TIMEZONE = "http://openid.net/schema/timezone";

    private OpenIdNamespaces() {
    }
}
