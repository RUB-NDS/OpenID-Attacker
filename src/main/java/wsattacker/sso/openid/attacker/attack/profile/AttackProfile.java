package wsattacker.sso.openid.attacker.attack.profile;

import java.lang.reflect.InvocationTargetException;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.commons.beanutils.BeanUtils;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameterKeeper;
import wsattacker.sso.openid.attacker.composition.AbstractBean;

@XmlRootElement(name = "Profile")
public class AttackProfile extends AbstractBean {

    private String name = "Profile Name";
    public static final String PROP_NAME = "name";
    private String description = "Profile Description";
    public static final String PROP_DESCRIPTION = "description";
    private AttackParameterKeeper configuration = new AttackParameterKeeper();
    public static final String PROP_CONFIGURATION = "configuration";

    /**
     * Get the value of configuration
     *
     * @return the value of configuration
     */
    @XmlElement(name = "Configuration")
    public AttackParameterKeeper getConfiguration() {
        return configuration;
    }

    /**
     * Set the value of configuration
     *
     * @param configuration new value of configuration
     */
    private void setConfiguration(AttackParameterKeeper configuration) {
        AttackParameterKeeper oldConfiguration = this.configuration;
        this.configuration = configuration;
        firePropertyChange(PROP_CONFIGURATION, oldConfiguration, configuration);
    }

    /**
     * Get the value of description
     *
     * @return the value of description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Set the value of description
     *
     * @param description new value of description
     */
    public void setDescription(String description) {
        String oldDescription = this.description;
        this.description = description;
        firePropertyChange(PROP_DESCRIPTION, oldDescription, description);
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

    public void updateConfiguration(AttackParameterKeeper configuration) {
        AttackParameterKeeper newConfiguration = new AttackParameterKeeper();
        try {
            BeanUtils.copyProperties(newConfiguration, configuration);
        } catch (IllegalAccessException | InvocationTargetException ex) {
            throw new IllegalStateException("Could not update configuration", ex);
        }
        setConfiguration(newConfiguration);
    }
}
