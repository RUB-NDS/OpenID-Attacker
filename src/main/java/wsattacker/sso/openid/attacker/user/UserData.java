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
