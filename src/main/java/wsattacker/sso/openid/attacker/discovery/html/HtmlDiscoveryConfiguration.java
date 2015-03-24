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
package wsattacker.sso.openid.attacker.discovery.html;

import java.io.Serializable;
import wsattacker.sso.openid.attacker.composition.AbstractBean;

public class HtmlDiscoveryConfiguration extends AbstractBean implements Serializable {

    public static final String PROP_BASEURL = "baseUrl";
    public static final String PROP_INCLUDEIDENTITY = "includeIdentity";
    public static final String PROP_IDENTITY = "identity";
    public static final String PROP_HTML = "html";
    public static final String PROP_OPENIDSERVER = "openidServer";
    public static final String PROP_OPENID2PROVIDER = "openId2Provider";
    private String baseUrl = "http://localhost:8080";
    private boolean includeIdentity = true;
    private String identity = "http://my.identity.com";
    private String html = "";
    private boolean openidServer = true;
    private boolean openId2Provider = true;

    private boolean includeXrdsHttpHeader = true;

    public static final String PROP_INCLUDEXRDSHTTPHEADER = "includeXrdsHttpHeader";

    /**
     * Get the value of includeXrdsHttpHeader
     *
     * @return the value of includeXrdsHttpHeader
     */
    public boolean isIncludeXrdsHttpHeader() {
        return includeXrdsHttpHeader;
    }

    /**
     * Set the value of includeXrdsHttpHeader
     *
     * @param includeXrdsHttpHeader new value of includeXrdsHttpHeader
     */
    public void setIncludeXrdsHttpHeader(boolean includeXrdsHttpHeader) {
        boolean oldIncludeXrdsHttpHeader = this.includeXrdsHttpHeader;
        this.includeXrdsHttpHeader = includeXrdsHttpHeader;
        firePropertyChange(PROP_INCLUDEXRDSHTTPHEADER, oldIncludeXrdsHttpHeader, includeXrdsHttpHeader);
    }

    public HtmlDiscoveryConfiguration() {
        updateHtml();
    }

    /**
     * Get the value of openidServer
     *
     * @return the value of openidServer
     */
    public boolean isOpenidServer() {
        return openidServer;
    }

    /**
     * Set the value of openidServer
     *
     * @param openidServer new value of openidServer
     */
    public void setOpenidServer(boolean openidServer) {
        boolean oldOpenidServer = this.openidServer;
        this.openidServer = openidServer;
        firePropertyChange(PROP_OPENIDSERVER, oldOpenidServer, openidServer);
        updateHtml();
    }

    /**
     * Get the value of openId2Provider
     *
     * @return the value of openId2Provider
     */
    public boolean isOpenId2Provider() {
        return openId2Provider;
    }

    /**
     * Set the value of openId2Provider
     *
     * @param openId2Provider new value of openId2Provider
     */
    public void setOpenId2Provider(boolean openId2Provider) {
        boolean oldOpenId2Provider = this.openId2Provider;
        this.openId2Provider = openId2Provider;
        firePropertyChange(PROP_OPENID2PROVIDER, oldOpenId2Provider, openId2Provider);
        updateHtml();
    }

    /**
     * Get the value of xml
     *
     * @return the value of xml
     */
    public String getHtml() {
        return html;
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
        updateHtml();
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
        updateHtml();
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
        updateHtml();
    }

    private void updateHtml() {
        setHtml(HtmlDiscoveryGenerator.generateString(this));
    }

    /**
     * Set the value of xml
     *
     * @param newHtml new value of xml
     */
    public void setHtml(String newHtml) {
        String oldHtml = this.html;
        this.html = newHtml;
//        this.html = "<html>\n"
//          + "<head >\n"
//          + "<title>http://john-doe1011.myopenid.com/</title>\n"
//          + "<link rel=\"openid.server\" href=\"http://www.myopenid.com/server\" />\n"
//          + "<link rel=\"openid2.provider\" href=\"http://www.myopenid.com/server\" />\n"
//          + "</head>\n"
//          + "<body >\n"
//          + "</body>\n"
//          + "</html>";
        firePropertyChange(PROP_HTML, oldHtml, newHtml);
    }
}
