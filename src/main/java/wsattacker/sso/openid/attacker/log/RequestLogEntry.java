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
package wsattacker.sso.openid.attacker.log;

import java.io.Serializable;
import java.util.Date;
import wsattacker.sso.openid.attacker.composition.AbstractBean;
import wsattacker.sso.openid.attacker.server.IdpType;

public class RequestLogEntry extends AbstractBean implements Serializable {

    public static final String PROP_TYPE = "type";
    public static final String PROP_DATE = "date";
    public static final String PROP_TEXT = "text";
    public static final String PROP_REQUEST = "request";
    public static final String PROP_RESPONSE = "response";
    public static final String PROP_IDPTYPE = "idpType";
    private RequestType type = RequestType.ASSOCIATION;
    final private Date date = new Date();
    private String text = "";
    private String request = "";
    private String response = "";
    private IdpType idpType = IdpType.ATTACKER;

    protected RequestLogEntry(RequestType type, String text, String request, String response, IdpType idpType) {
        this.text = text;
        this.type = type;
        this.request = request;
        this.response = response;
        this.idpType = idpType;
    }

    /**
     * Get the value of request
     *
     * @return the value of request
     */
    public String getRequest() {
        return request;
    }

    /**
     * Set the value of request
     *
     * @param request new value of request
     */
    public void setRequest(String request) {
        String oldRequest = this.request;
        this.request = request;
        firePropertyChange(PROP_REQUEST, oldRequest, request);
    }

    /**
     * Get the value of response
     *
     * @return the value of response
     */
    public String getResponse() {
        return response;
    }

    /**
     * Set the value of response
     *
     * @param response new value of response
     */
    public void setResponse(String response) {
        String oldResponse = this.response;
        this.response = response;
        firePropertyChange(PROP_RESPONSE, oldResponse, response);
    }

    /**
     * Get the value of date
     *
     * @return the value of date
     */
    public Date getDate() {
        return date;
    }

    /**
     * Get the value of text
     *
     * @return the value of text
     */
    public String getText() {
        return text;
    }

    /**
     * Set the value of text
     *
     * @param text new value of text
     */
    public void setText(String text) {
        String oldText = this.text;
        this.text = text;
        firePropertyChange(PROP_TEXT, oldText, text);
    }

    /**
     * Get the value of type
     *
     * @return the value of type
     */
    public RequestType getType() {
        return type;
    }

    /**
     * Set the value of type
     *
     * @param type new value of type
     */
    public void setType(RequestType type) {
        RequestType oldType = this.type;
        this.type = type;
        firePropertyChange(PROP_TYPE, oldType, type);
    }
    
    /**
     * Get the value of idpType
     *
     * @return the value of idpType
     */
    public IdpType getIdpType() {
        return idpType;
    }

    /**
     * Set the value of idpType
     *
     * @param idpType new value of idpType
     */
    public void setIdpType(IdpType idpType) {
        IdpType oldIdpType = this.idpType;
        this.idpType = idpType;
        firePropertyChange(PROP_IDPTYPE, oldIdpType, idpType);
    }
}
