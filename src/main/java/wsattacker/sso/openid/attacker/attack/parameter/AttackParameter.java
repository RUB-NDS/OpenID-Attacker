package wsattacker.sso.openid.attacker.attack.parameter;

import java.io.Serializable;
import java.util.Objects;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import wsattacker.sso.openid.attacker.attack.parameter.utilities.AttackValue;
import wsattacker.sso.openid.attacker.attack.parameter.utilities.HttpMethod;
import wsattacker.sso.openid.attacker.composition.AbstractBean;
import wsattacker.sso.openid.attacker.server.buisinesslogic.CustomOpenIdProcessor;

@XmlRootElement(name = "AttackParameter")
public class AttackParameter extends AbstractBean implements Serializable {

    public static final String PROP_NAME = "name";
    public static final String PROP_VALIDVALUE = "validValue";
    public static final String PROP_ATTACKVALUE = "attackValue";
    public static final String PROP_ATTACKVALUEUSEDFORSIGNATURECOMPUTATION = "attackValueUsedForSignatureComputation";
    public static final String PROP_VALIDMETHOD = "validMethod";
    public static final String PROP_ATTACKMETHOD = "attackMethod";
    public static final String PROP_INVALIDSIGNATURE = "inValidSignature";
    public static final String PROP_INATTACKSIGNATURE = "inAttackSignature";
    private static final Log LOG = LogFactory.getLog(CustomOpenIdProcessor.class);

    public static AttackParameter createWithNameAndValidValue(String name, String validValue) {
        AttackParameter result;
//        switch (name) {
//            case "openid.return_to":
//                result = new SearchReplaceAttackParameter();
//                break;
//            default:
//                result = new AttackParameter();
//        }
        result = new SearchReplaceAttackParameter();
        result.setName(name);
        result.setValidValue(validValue);
        return result;
    }
    private boolean inValidSignature = false;
    private boolean inAttackSignature = false;
    private String name = "parameterName";
    private String validValue = "validValue";
    private AttackValue attackValue = new AttackValue();
    private HttpMethod validMethod = HttpMethod.GET;
    private HttpMethod attackMethod = HttpMethod.DO_NOT_SEND;

    public AttackParameter() {
    }

    public boolean isInAttackSignature() {
        return inAttackSignature;
    }

    public boolean isInValidSignature() {
        return inValidSignature;
    }

    public String getName() {
        return name;
    }

    public String getValidValue() {
        return validValue;
    }

    public void setValidValue(String validValue) {
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("--> Parameter '%s' --> setValidValue to: '%s'", name, validValue));
        }
        String oldValidValue = this.validValue;
        this.validValue = validValue;
        firePropertyChange(PROP_VALIDVALUE, oldValidValue, validValue);
    }

    public String getAttackValue() {
        return attackValue.getCurrentValue();
    }

    public void setAttackValue(String value) {
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("--> Parameter '%s' --> setAttackValue to: '%s'", name, value));
        }
        String oldAttackValue = attackValue.getCurrentValue();
        attackValue.setCurrentValue(value);
        firePropertyChange(PROP_ATTACKVALUE, oldAttackValue, value);
    }

    protected void setUserAttackValue(String value) {
        attackValue.setUserValue(value);
    }

    protected void setAutomaticValue(String value) {
        String oldAttackValue = attackValue.getAutomaticValue();
        attackValue.setAutomaticValue(value);
        if (!isAttackValueUsedForSignatureComputation()) {
            firePropertyChange(PROP_ATTACKVALUE, oldAttackValue, value);
        }
    }

    public boolean isAttackValueUsedForSignatureComputation() {
        return attackValue.isEnableUserValue();
    }

    public void setAttackValueUsedForSignatureComputation(boolean enableForSignature) {
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("--> Parameter '%s' --> setAttackValueUsedForSignatureComputation to: '%b'", name, enableForSignature));
        }
        boolean oldAttackEnabled = attackValue.isEnableUserValue();
        String oldAttackValue = attackValue.getCurrentValue();
        attackValue.setEnableUserValue(enableForSignature);
        firePropertyChange(PROP_ATTACKVALUEUSEDFORSIGNATURECOMPUTATION, oldAttackEnabled, enableForSignature);
        firePropertyChange(PROP_ATTACKVALUE, oldAttackValue, enableForSignature);

        if (enableForSignature && validMethod.equals(HttpMethod.GET) && attackMethod.equals(HttpMethod.DO_NOT_SEND)) {
            setValidMethod(HttpMethod.DO_NOT_SEND);
            setAttackMethod(HttpMethod.GET);
        } else if (!enableForSignature && validMethod.equals(HttpMethod.DO_NOT_SEND) && attackMethod.equals(HttpMethod.GET)) {
            setValidMethod(HttpMethod.GET);
            setAttackMethod(HttpMethod.DO_NOT_SEND);
        }
    }

    public HttpMethod getValidMethod() {
        return validMethod;
    }

    public void setValidMethod(HttpMethod validMethod) {
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("--> Parameter '%s' --> setValidMethod to: '%s'", name, validMethod));
        }
        HttpMethod oldValidMethod = this.validMethod;
        this.validMethod = validMethod;
        firePropertyChange(PROP_VALIDMETHOD, oldValidMethod, validMethod);
    }

    public HttpMethod getAttackMethod() {
        return attackMethod;
    }

    public void setAttackMethod(HttpMethod attackMethod) {
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("--> Parameter '%s' --> setAttackMethod to: '%s'", name, attackMethod));
        }
        HttpMethod oldAttackMethod = this.attackMethod;
        this.attackMethod = attackMethod;
        firePropertyChange(PROP_ATTACKMETHOD, oldAttackMethod, attackMethod);
    }

    @Override
    public String toString() {
        return "OpenIdAttackParameter{" + "name=" + name + ", validValue=" + validValue + ", attackValue=" + attackValue + ", validMethod=" + validMethod + ", attackMethod=" + attackMethod + '}';
    }

    public void setName(String name) {
        if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("--> Parameter '%s' --> setName to: '%s'", this.name, name));
        }
        String oldName = this.name;
        this.name = name;
        firePropertyChange(PROP_NAME, oldName, name);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 43 * hash + (this.inValidSignature ? 1 : 0);
        hash = 43 * hash + (this.inAttackSignature ? 1 : 0);
        hash = 43 * hash + Objects.hashCode(this.name);
        hash = 43 * hash + Objects.hashCode(this.validValue);
        hash = 43 * hash + Objects.hashCode(this.attackValue);
        hash = 43 * hash + Objects.hashCode(this.validMethod);
        hash = 43 * hash + Objects.hashCode(this.attackMethod);
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
        final AttackParameter other = (AttackParameter) obj;
        if (this.inValidSignature != other.inValidSignature) {
            return false;
        }
        if (this.inAttackSignature != other.inAttackSignature) {
            return false;
        }
        if (!Objects.equals(this.name, other.name)) {
            return false;
        }
        if (!Objects.equals(this.validValue, other.validValue)) {
            return false;
        }
        if (!Objects.equals(this.attackValue, other.attackValue)) {
            return false;
        }
        if (this.validMethod != other.validMethod) {
            return false;
        }
        if (this.attackMethod != other.attackMethod) {
            return false;
        }
        return true;
    }

    protected void setInAttackSignature(boolean inAttackSignature) {
        boolean oldInAttackSignature = this.inAttackSignature;
        this.inAttackSignature = inAttackSignature;
        firePropertyChange(PROP_INATTACKSIGNATURE, oldInAttackSignature, inAttackSignature);
    }

    protected void setInValidSignature(boolean inValidSignature) {
        boolean oldInValidSignature = this.inValidSignature;
        this.inValidSignature = inValidSignature;
        firePropertyChange(PROP_INVALIDSIGNATURE, oldInValidSignature, inValidSignature);
    }
}
