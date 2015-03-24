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
package wsattacker.sso.openid.attacker.discovery.xrds;

import java.io.Serializable;
import wsattacker.sso.openid.attacker.composition.AbstractBean;

public class XrdsConfiguration extends AbstractBean implements Serializable {

    public static final String PROP_BASEURL = "baseUrl";
    public static final String PROP_OPENIDVERSION = "openIdVersion";
    public static final String PROP_INCLUDEIDENTITY = "includeIdentity";
    public static final String PROP_IDENTITY = "identity";
    private String baseUrl = "http://localhost:8080";
    private OpenIdVersion openIdVersion = OpenIdVersion.VERSION_20_CLAIMED_IDENTIFIER_ELEMENT;
    private boolean includeIdentity = true;
    private String identity = "http://my.identity.com";
    private int priority = 10;
    public static final String PROP_PRIORITY = "priority";
    private String xml = "";
    public static final String PROP_XML = "xml";

    public XrdsConfiguration() {
        updateXml();
    }

    /**
     * Get the value of xml
     *
     * @return the value of xml
     */
    public String getXml() {
        return xml;
    }

    private void updateXml() {
        setXml(XrdsGenerator.generateString(this));
    }

    /**
     * Set the value of xml
     *
     * @param xml new value of xml
     */
    public void setXml(String xml) {
        String oldXml = this.xml;
        this.xml = xml;
        firePropertyChange(PROP_XML, oldXml, xml);
    }

    /**
     * Get the value of priority
     *
     * @return the value of priority
     */
    public int getPriority() {
        return priority;
    }

    /**
     * Set the value of priority
     *
     * @param priority new value of priority
     */
    public void setPriority(int priority) {
        int oldPriority = this.priority;
        this.priority = priority;
        firePropertyChange(PROP_PRIORITY, oldPriority, priority);
        updateXml();
    }

    /**
     * Get the value of identity
     *
     * @return the value of identity
     */
    public String getIdentity() {
        return identity;
    }

    /**
     * Set the value of identity
     *
     * @param identity new value of identity
     */
    public void setIdentity(String identity) {
        String oldIdentity = this.identity;
        this.identity = identity;
        firePropertyChange(PROP_IDENTITY, oldIdentity, identity);
        updateXml();
    }

    /**
     * Get the value of includeIdentity
     *
     * @return the value of includeIdentity
     */
    public boolean isIncludeIdentity() {
        return includeIdentity;
    }

    /**
     * Set the value of includeIdentity
     *
     * @param includeIdentity new value of includeIdentity
     */
    public void setIncludeIdentity(boolean includeIdentity) {
        boolean oldIncludeIdentity = this.includeIdentity;
        this.includeIdentity = includeIdentity;
        firePropertyChange(PROP_INCLUDEIDENTITY, oldIncludeIdentity, includeIdentity);
        updateXml();
    }

    /**
     * Get the value of baseUrl
     *
     * @return the value of baseUrl
     */
    public String getBaseUrl() {
        return baseUrl;
    }

    /**
     * Set the value of baseUrl
     *
     * @param baseUrl new value of baseUrl
     */
    public void setBaseUrl(String baseUrl) {
        String oldBaseUrl = this.baseUrl;
        this.baseUrl = baseUrl;
        firePropertyChange(PROP_BASEURL, oldBaseUrl, baseUrl);
        updateXml();
    }

    /**
     * Get the value of openIdVersion
     *
     * @return the value of openIdVersion
     */
    public OpenIdVersion getOpenIdVersion() {
        return openIdVersion;
    }

    /**
     * Set the value of openIdVersion
     *
     * @param openIdVersion new value of openIdVersion
     */
    public void setOpenIdVersion(OpenIdVersion openIdVersion) {
        OpenIdVersion oldOpenIdVersion = this.openIdVersion;
        this.openIdVersion = openIdVersion;
        firePropertyChange(PROP_OPENIDVERSION, oldOpenIdVersion, openIdVersion);
        updateXml();
    }
}
