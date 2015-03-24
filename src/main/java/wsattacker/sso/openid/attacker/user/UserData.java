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

import javax.xml.bind.annotation.XmlRootElement;
import wsattacker.sso.openid.attacker.composition.AbstractBean;

@XmlRootElement(name = "Data")
public class UserData extends AbstractBean {

    public static final String PROP_NAME = "name";
    public static final String PROP_VALUE = "value";
    private String name = "newName";
    private String value = "newValue";
    
    

    /**
     * Get the value of value
     *
     * @return the value of value
     */
    public String getValue() {
        return value;
    }

    /**
     * Set the value of value
     *
     * @param value new value of value
     */
    public void setValue(String value) {
        String oldValue = this.value;
        this.value = value;
        firePropertyChange(PROP_VALUE, oldValue, value);
    }

    /**
     * Get the value of name
     *
     * @return the value of name
     */
    public String getName() {
        return name;
    }

    /**
     * Set the value of name
     *
     * @param name new value of name
     */
    public void setName(String name) {
        String oldName = this.name;
        this.name = name;
        firePropertyChange(PROP_NAME, oldName, name);
    }

    @Override
    public String toString() {
        return "UserData{" + "name=" + name + ", value=" + value + '}';
    }
}
