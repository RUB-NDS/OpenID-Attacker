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
package wsattacker.sso.openid.attacker.server.buisinesslogic;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openid4java.association.Association;
import org.openid4java.association.AssociationException;
import org.openid4java.server.ServerAssociationStore;
import wsattacker.sso.openid.attacker.composition.AbstractBean;

/**
 * This is basically a Copy of the original class
 * org.openid4java.server.InMemoryServerAssociationStore
 * by Marius Scurtescu, Johnny Bufu
 * We just added some functionality for more flexibility for the
 * assoc value creation.
 */
@XmlRootElement(name = "AssociationStore")
public class CustomInMemoryServerAssociationStore extends AbstractBean implements ServerAssociationStore {

    public static final String PROP_ASSOCIATIONPREFIX = "associationPrefix";
    private static final Log LOG = LogFactory.getLog(CustomInMemoryServerAssociationStore.class);
    private static final boolean DEBUG = LOG.isDebugEnabled();
    private String associationPrefix;
    private int counter;
    private final Map<String, Association> _handleMap;
    private List<Association> associationList = new ArrayList();
    public static final String PROP_ASSOCIATIONLIST = "associationList";

    /**
     * Get the value of associationList
     *
     * @return the value of associationList
     */
    @XmlElementWrapper
    @XmlElement(name = "Association", type = Association.class)
    public List<Association> getAssociationList() {
        return associationList;
    }

    /**
     * Set the value of associationList
     *
     * @param associationList new value of associationList
     */
    public void setAssociationList(List<Association> associationList) {
        List<Association> oldAssociationList = this.associationList;
        this.associationList = associationList;
        firePropertyChange(PROP_ASSOCIATIONLIST, oldAssociationList, associationList);
    }

    public CustomInMemoryServerAssociationStore() {
        associationPrefix = Long.toString(new Date().getTime());
        counter = 0;
        _handleMap = new HashMap<>();
    }

    public void setAssociationPrefix(String associationPrefix) {
        this.counter = 0;
        String oldAssociationPrefix = this.associationPrefix;
        this.associationPrefix = associationPrefix;
        firePropertyChange(PROP_ASSOCIATIONPREFIX, oldAssociationPrefix, associationPrefix);
    }

    @Override
    public synchronized Association generate(String type, int expiryIn)
      throws AssociationException {
        removeExpired();

        String handle;
        // If this is the first, just use the prefix
        handle = associationPrefix;
        while (_handleMap.containsKey(handle)) {
            // Otherwise, use prefix plus counter
            ++counter;
            handle = associationPrefix + "-" + counter;
        }

        Association association = Association.generate(type, handle, expiryIn);

        _handleMap.put(handle, association);

        if (DEBUG) {
            LOG.debug("Generated association, handle: " + handle
              + " type: " + type
              + " expires in: " + expiryIn + " seconds.");
        }
        removeExpired();

        return association;
    }

    @Override
    public synchronized Association load(String handle) {
        removeExpired();

        return (Association) _handleMap.get(handle);
    }

    @Override
    public synchronized void remove(String handle) {
        if (DEBUG) {
            LOG.debug("Removing association, handle: " + handle);
        }

        _handleMap.remove(handle);

        removeExpired();
    }

    public String getAssociationPrefix() {
        return associationPrefix;
    }

    private synchronized void removeExpired() {
        Set handleToRemove = new HashSet();
        for (String handle : _handleMap.keySet()) {

            Association association = (Association) _handleMap.get(handle);

            if (association.hasExpired()) {
                handleToRemove.add(handle);
            }
        }

        Iterator handles = handleToRemove.iterator();
        boolean hasRemovedAtLeastOne = false;
        while (handles.hasNext()) {
            String handle = (String) handles.next();

            if (DEBUG) {
                LOG.debug(String.format("Removing expired association, handle: %s", handle));
            }

            _handleMap.remove(handle);
            hasRemovedAtLeastOne = true;
        }
        if (hasRemovedAtLeastOne || _handleMap.size() != associationList.size()) {
            setAssociationList(new ArrayList<>(_handleMap.values()));
        }
    }

    protected synchronized int size() {
        return _handleMap.size();
    }
}
