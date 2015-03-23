package wsattacker.sso.openid.attacker.log;

import java.util.Date;
import wsattacker.sso.openid.attacker.composition.AbstractBean;

public class RequestLogEntry extends AbstractBean {

    public static final String PROP_TYPE = "type";
    public static final String PROP_DATE = "date";
    public static final String PROP_TEXT = "text";
    public static final String PROP_REQUEST = "request";
    public static final String PROP_RESPONSE = "response";
    private RequestType type = RequestType.ASSOCIATION;
    final private Date date = new Date();
    private String text = "";
    private String request = "";
    private String response = "";

    protected RequestLogEntry(RequestType type, String text, String request, String response) {
        this.text = text;
        this.type = type;
        this.request = request;
        this.response = response;
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
}
