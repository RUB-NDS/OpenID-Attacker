package wsattacker.sso.openid.attacker.attack.parameter.utilities;

import java.io.Serializable;
import java.util.Objects;

public class AttackValue implements Serializable {

    private boolean enableUserValue = false;
    private String userValue = null;
    private String automaticValue = "attackAutomaticValue";

    /**
     * Get the value of enableUserValue
     *
     * @return the value of enableUserValue
     */
    public boolean isEnableUserValue() {
        return enableUserValue;
    }

    /**
     * Set the value of attackEnabled
     *
     * @param enableUserValue new value of enableUserValue
     */
    public void setEnableUserValue(boolean enableUserValue) {
        this.enableUserValue = enableUserValue;
    }

    /**
     * Get the value of userValue
     *
     * @return the value of userValue
     */
    public String getUserValue() {
        // if user value is not yet set, copy it from automatic value
        if (this.userValue == null) {
            this.userValue = automaticValue;
        }
        return userValue;
    }

    /**
     * Set the value of userValue
     *
     * @param userValue new value of userValue
     */
    public void setUserValue(String userValue) {
        this.userValue = userValue;
    }

    /**
     * Get the value of automaticValue
     *
     * @return the value of automaticValue
     */
    public String getAutomaticValue() {
        return automaticValue;
    }

    /**
     * Set the value of automaticValue
     *
     * @param automaticValue new value of automaticValue
     */
    public void setAutomaticValue(String automaticValue) {
        this.automaticValue = automaticValue;
    }

    @Override
    public String toString() {
        return "AttackValue{" + "attackEnabled=" + enableUserValue + ", userValue=" + userValue + ", automaticValue=" + automaticValue + '}';
    }

    public String getCurrentValue() {
        String result;
        if (isEnableUserValue()) {
            result = getUserValue();
        } else {
            result = getAutomaticValue();
        }
        return result;
    }

    public void setCurrentValue(String value) {
        if (isEnableUserValue()) {
            setUserValue(value);
        } else {
            setAutomaticValue(value);
        }
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 31 * hash + (this.enableUserValue ? 1 : 0);
        hash = 31 * hash + Objects.hashCode(this.userValue);
        hash = 31 * hash + Objects.hashCode(this.automaticValue);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final AttackValue other = (AttackValue) obj;
        if (this.enableUserValue != other.enableUserValue) {
            return false;
        }
        if (!Objects.equals(this.userValue, other.userValue)) {
            return false;
        }
        if (!Objects.equals(this.automaticValue, other.automaticValue)) {
            return false;
        }
        return true;
    }
}
