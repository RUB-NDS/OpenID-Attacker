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

import java.util.ArrayList;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import org.jdesktop.observablecollections.ObservableCollections;
import org.jdesktop.observablecollections.ObservableList;
import wsattacker.sso.openid.attacker.composition.AbstractBean;

@XmlRootElement(name = "DataCollector")
public class UserDataCollector extends AbstractBean {

    private ObservableList<UserData> dataList = ObservableCollections.observableList(new ArrayList<UserData>());
    public static final String PROP_DATALIST = "dataList";

    /**
     * Get the value of dataList
     *
     * @return the value of dataList
     */
    @XmlElement(name = "Data")
    public ObservableList<UserData> getDataList() {
        return dataList;
    }

    /**
     * Set the value of dataList
     *
     * @param dataList new value of dataList
     */
    public void setDataList(ObservableList<UserData> dataList) {
        ObservableList<UserData> oldDataList = this.dataList;
        this.dataList = dataList;
        firePropertyChange(PROP_DATALIST, oldDataList, dataList);
    }

    public UserData getByName(String name) {
        for (UserData data : dataList) {
            if (name.equals(data.getName())) {
                return data;
            }
        }
        throw new IllegalArgumentException(String.format("No such element '%s'", name));
    }

    public boolean has(String name) {
        boolean result = false;
        for (UserData data : dataList) {
            if (name.equals(data.getName())) {
                result = true;
            }
        }
        return result;
    }

    public UserData addOne() {
        UserData newData = new UserData();
        dataList.add(newData);
        return newData;
    }

    public UserData addOne(String name, String value) {
        UserData newData = addOne();
        newData.setName(name);
        newData.setValue(value);
        return newData;
    }

    public UserData removeByName(String name) {
        UserData removed = getByName(name);
        dataList.remove(removed);
        return removed;
    }

    public UserData removeById(int id) {
        return dataList.remove(id);
    }

    public void set(String name, String value) {
        try {
            UserData contained = getByName(name);
            contained.setValue(value);
        } catch (IllegalArgumentException e) {
            addOne(name, value);
        }
    }
}
