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
package wsattacker.sso.openid.attacker.attack.parameter;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import javax.xml.bind.annotation.XmlRootElement;
import org.jdesktop.observablecollections.ObservableCollections;
import org.jdesktop.observablecollections.ObservableList;
import org.jdesktop.observablecollections.ObservableListListener;
import wsattacker.sso.openid.attacker.attack.parameter.utilities.HttpMethod;
import wsattacker.sso.openid.attacker.composition.AbstractBean;
import wsattacker.sso.openid.attacker.config.OpenIdServerConfiguration;
import wsattacker.sso.openid.attacker.user.UserDataCollector;

@XmlRootElement(name = "AttackParameters")
public class AttackParameterKeeper extends AbstractBean implements Serializable, Iterable<AttackParameter>, ObservableListListener, PropertyChangeListener {

    public static final String PREFIX_OPENID = "openid.";
    public static final String OPENID_SIGNED = "openid.signed";
    public static final String PROP_PARAMETERLIST = "parameterList";
    private List<AttackParameter> parameterList;

    public AttackParameterKeeper() {
        List<AttackParameter> listToObserve = new ArrayList<>();
        ObservableList<AttackParameter> observableList = ObservableCollections.observableList(listToObserve);
        observableList.addObservableListListener(this);
        this.parameterList = observableList;
    }

    /**
     * Get the value of parameterList
     *
     * @return the value of parameterList
     */
    public List<AttackParameter> getParameterList() {
        return parameterList;
    }

    /**
     * Set the value of parameterList
     *
     * @param parameterList new value of parameterList
     */
    public void setParameterList(List<AttackParameter> parameterList) {
        List<AttackParameter> oldParameterList = this.parameterList;
        this.parameterList = parameterList;
        firePropertyChange(PROP_PARAMETERLIST, oldParameterList, parameterList);
    }

    public AttackParameter getParameter(final int index) {
        return parameterList.get(index);
    }

    public AttackParameter getParameter(final String name) {
        AttackParameter result = null;
        for (AttackParameter p : parameterList) {
            if (p.getName().equals(name)) {
                result = p;
                break;
            }
        }
        return result;
    }

    public AttackParameter removeParameter(final int index) {
        return parameterList.remove(index);
    }

    public AttackParameter removeParameter(final String name) {
        AttackParameter toRemove = getParameter(name);
        parameterList.remove(toRemove);
        return toRemove;
    }

    public void clear() {
        parameterList.clear();
    }

    public Set<String> keySet() {
        Set<String> keySet = new HashSet<>();
        for (AttackParameter p : parameterList) {
            keySet.add(p.getName());
        }
        return keySet;
    }

    public void addParameter(AttackParameter newParameter) {
        String name = newParameter.getName();
        if (hasParameter(name)) {
            throw new IllegalArgumentException(String.format("Parameter with name %s already contained", name));
        }
        parameterList.add(newParameter);
    }

    public AttackParameter addOrUpdateParameterValidValue(final String name, final String validValue) {
        AttackParameter result = getParameter(name);
        if (result != null) {
            result.setValidValue(validValue);
        } else {
            AttackParameter newParameter = AttackParameter.createWithNameAndValidValue(name, validValue);

            // TODO: Move this to a better position
            UserDataCollector attackData = OpenIdServerConfiguration.getAttackerInstance().getAttackData();
            if (attackData.has(name)) {
                newParameter.setUserAttackValue(attackData.getByName(name).getValue());
            }
            parameterList.add(newParameter);
            result = newParameter;
        }
        return result;
    }

    @Override
    public String toString() {
        return "OpenIdAttackParameterKeeper{" + "parameterMap=" + parameterList + '}';
    }

    public boolean hasParameter(String name) {
        boolean result = false;
        for (AttackParameter p : parameterList) {
            if (p.getName().equals(name)) {
                result = true;
                break;
            }
        }
        return result;
    }

    @Override
    public Iterator<AttackParameter> iterator() {
        return parameterList.iterator();
    }

    @Override
    public void propertyChange(PropertyChangeEvent pce) {
        AttackParameter p = (AttackParameter) pce.getSource();
        handleSignedParameter(p);
    }

    @Override
    public void listElementsAdded(ObservableList list, int index, int length) {
        List<AttackParameter> addedAttackParameters = (List<AttackParameter>) list;
        boolean signedChanged = false;
        int last = index + length;
        for (int i = index; i < last; ++i) {
            AttackParameter addedParameter = addedAttackParameters.get(i);
            String addedName = addedParameter.getName();
            if (OPENID_SIGNED.equals(addedName)) {
                addedParameter.addPropertyChangeListener(AttackParameter.PROP_VALIDVALUE, this);
                addedParameter.addPropertyChangeListener(AttackParameter.PROP_ATTACKVALUE, this);
                handleSignedParameter(addedParameter);
                break;
            }
        }
    }

    @Override
    public void listElementsRemoved(ObservableList list, int index, List oldElements) {
        List<AttackParameter> removedAttackParameter = (List<AttackParameter>) oldElements;
        boolean signedChanged = false;
        for (AttackParameter removedParameter : removedAttackParameter) {
            String removedName = removedParameter.getName();
            if (OPENID_SIGNED.equals(removedName)) {
                removedParameter.removePropertyChangeListener(AttackParameter.PROP_VALIDVALUE, this);
                removedParameter.removePropertyChangeListener(AttackParameter.PROP_ATTACKVALUE, this);
                setInEverySignatureToFalse();
                break;
            }
        }
    }

    @Override
    public void listElementReplaced(ObservableList list, int index, Object oldElement) {
        AttackParameter oldParameter = (AttackParameter) oldElement;
        String oldName = oldParameter.getName();
        if (OPENID_SIGNED.equals(oldName)) {
            oldParameter.removePropertyChangeListener(AttackParameter.PROP_VALIDVALUE, this);
            oldParameter.removePropertyChangeListener(AttackParameter.PROP_ATTACKVALUE, this);
            setInEverySignatureToFalse();
        }
        AttackParameter newParameter = (AttackParameter) list.get(index);
        String newName = newParameter.getName();
        if (OPENID_SIGNED.equals(newName)) {
            newParameter.addPropertyChangeListener(AttackParameter.PROP_VALIDVALUE, this);
            newParameter.addPropertyChangeListener(AttackParameter.PROP_ATTACKVALUE, this);
            handleSignedParameter(newParameter);
        }
    }

    @Override
    public void listElementPropertyChanged(ObservableList list, int index) {
        AttackParameter p = (AttackParameter) list.get(index);
        String name = p.getName();
        if (OPENID_SIGNED.equals(name)) {
            handleSignedParameter(p);
        }
    }

    private void handleSignedParameter(AttackParameter signedParameter) {
        setInValidSignatureForAllParameters(signedParameter);
        setInAttackSignatureForAllParameters(signedParameter);
    }

    private void setInValidSignatureForAllParameters(AttackParameter signedParameter) {
        String signedValue = signedParameter.getValidValue();
        Set<String> signedSet = createSignedSet(signedValue);
        for (AttackParameter parameter : parameterList) {
            boolean isSigned = signedSet.contains(parameter.getName());
            parameter.setInValidSignature(isSigned);
        }
    }

    private void setInAttackSignatureForAllParameters(AttackParameter signedParameter) {
        String signedValue = signedParameter.getAttackValue();
        Set<String> signedSet = createSignedSet(signedValue);
        for (AttackParameter parameter : parameterList) {
            boolean isSigned = signedSet.contains(parameter.getName());
            parameter.setInAttackSignature(isSigned);
        }
    }

    private void setInEverySignatureToFalse() {
        for (AttackParameter parameter : parameterList) {
            parameter.setInValidSignature(false);
            parameter.setInAttackSignature(false);
        }
    }

    private Set<String> createSignedSet(String signedValue) {
        Set<String> signedSet = new HashSet<>();
        if (signedValue != null) {
            for (String theSigned : signedValue.split(",")) {
                signedSet.add(PREFIX_OPENID + theSigned);
            }
        }
        return signedSet;
    }

    public void moveUp(AttackParameter parameter) {
        int index = parameterList.indexOf(parameter);
        if (index > 0) {
            Collections.swap(parameterList, index, index - 1);
        }
    }

    public void moveDown(AttackParameter parameter) {
        int index = parameterList.indexOf(parameter);
        int last = parameterList.size() - 1;
        if (index < last) {
            Collections.swap(parameterList, index, index + 1);
        }
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 83 * hash + Objects.hashCode(this.parameterList);
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
        final AttackParameterKeeper other = (AttackParameterKeeper) obj;
        if (!Objects.equals(this.parameterList, other.parameterList)) {
            return false;
        }
        return true;
    }
    
    public void resetAllParameters() {
        for (AttackParameter param : parameterList) {
            // reset methods
            param.setValidMethod(HttpMethod.GET);
            param.setAttackMethod(HttpMethod.DO_NOT_SEND);
            
            // disable "modify for attack signature computation"
            param.setAttackValueUsedForSignatureComputation(false);
        }
    }
}
