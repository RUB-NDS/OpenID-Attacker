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
package wsattacker.sso.openid.attacker.user;

import java.util.LinkedHashMap;
import java.util.Map;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

@XmlRootElement(name = "User")
public class User extends UserDataCollector {

    public static final String NAME_IDENTIFIER = "identity";
    public static final String NAME_CLAIMED_ID = "claimed_id";

    public User() {
        super();
        setIdentifier(NAME_IDENTIFIER);
        setClaimedId(NAME_CLAIMED_ID);
    }

    @XmlTransient
    public String getIdentifier() {
        return getByName(NAME_IDENTIFIER).getValue();
    }

    public void setIdentifier(String identifier) {
        set(NAME_IDENTIFIER, identifier);
    }

    @XmlTransient
    public String getClaimedId() {
        return getByName(NAME_CLAIMED_ID).getValue();
    }

    public void setClaimedId(String claimedId) {
        set(NAME_CLAIMED_ID, claimedId);
    }

    public Map getUserDataMap() {
        Map<String, String> result = new LinkedHashMap<>();
        for (UserData data : getDataList()) {
            String name = data.getName();
            if (!result.containsKey(name)) {
                String value = data.getValue();
                result.put(name, value);
            }
        }
        return result;
    }
}
