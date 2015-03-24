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

public final class OpenIdElementNames {

    public static final String MODE = "mode";
    public static final String IDENTIFIER = "identifier";
    public static final String CLAIMED_ID = "claimed_id";
    public static final String OP_ENDPOINT = "op_endpoint";
    public static final String ASSOC_HANDLE = "assoc_handle";
    public static final String SIGNATURE = "sig";
    public static final String SIGNED_FIELDS = "signed";
    public static final String NICKNAME = "nickname"; // 'http://axschema.org/namePerson/friendly'
    public static final String EMAIL = "email"; // 'http://axschema.org/contact/email'
    public static final String FULLNAME = "fullname"; // 'http://axschema.org/namePerson'
    public static final String DOB = "dob"; // 'http://axschema.org/birthDate'
    public static final String GENDER = "gender"; // 'http://axschema.org/person/gender'
    public static final String POSTCODE = "postcode"; // 'http://axschema.org/contact/postalCode/home'
    public static final String COUNTRY = "country"; // 'http://axschema.org/contact/country/home'
    public static final String LANGUAGE = "language"; // 'http://axschema.org/pref/language'
    public static final String TIMEZONE = "timezone"; // 'http://axschema.org/pref/timezone'

    private OpenIdElementNames() {
    }
}
