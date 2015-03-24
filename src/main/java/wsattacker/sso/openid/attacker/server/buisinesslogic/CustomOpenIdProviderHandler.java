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

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.IOException;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.TransformerException;
import org.apache.log4j.Logger;
import org.eclipse.jetty.http.HttpURI;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.openid4java.message.DirectError;
import org.openid4java.message.Message;
import org.openid4java.message.ParameterList;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameterHandler;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameterKeeper;
import wsattacker.sso.openid.attacker.attack.parameter.utilities.HttpMethod;
import wsattacker.sso.openid.attacker.config.OpenIdServerConfiguration;
import wsattacker.sso.openid.attacker.discovery.html.HtmlDiscoveryConfiguration;
import wsattacker.sso.openid.attacker.log.RequestLogger;
import wsattacker.sso.openid.attacker.log.RequestType;
import wsattacker.sso.openid.attacker.log.utilities.PrintHelper;
import wsattacker.sso.openid.attacker.server.IdpType;
import wsattacker.sso.openid.attacker.server.exception.OpenIdAttackerServerException;
import wsattacker.sso.openid.attacker.server.utilities.HttpPostRedirect;

public class CustomOpenIdProviderHandler extends AbstractHandler {

    public static final String PROP_OPENIDPROCESSOR = "openIdProcessor";
    private static final Logger LOG = Logger.getLogger(CustomOpenIdProviderHandler.class.getName());
    private final transient PropertyChangeSupport propertyChangeSupport = new java.beans.PropertyChangeSupport(this);
    private CustomOpenIdProcessor openIdProcessor;
    private IdpType idpType;

    public CustomOpenIdProviderHandler() {
        this(IdpType.ATTACKER);
    }
    
    public CustomOpenIdProviderHandler(IdpType idpType) {
        super();
        
        openIdProcessor = new CustomOpenIdProcessor(idpType);
        
        this.idpType = idpType;
    }

    /**
     * Add PropertyChangeListener.
     *
     * @param listener
     */
    final public void addPropertyChangeListener(PropertyChangeListener listener) {
        propertyChangeSupport.addPropertyChangeListener(listener);
    }

    final public void addPropertyChangeListener(String propertyName, PropertyChangeListener listener) {
        propertyChangeSupport.addPropertyChangeListener(propertyName, listener);
    }

    /**
     * Remove PropertyChangeListener.
     *
     * @param listener
     */
    final public void removePropertyChangeListener(PropertyChangeListener listener) {
        propertyChangeSupport.removePropertyChangeListener(listener);
    }

    final public void removePropertyChangeListener(String propertyName, PropertyChangeListener listener) {
        propertyChangeSupport.removePropertyChangeListener(propertyName, listener);
    }

    public void handleXrdsRequest(String info, HttpServletResponse response) throws TransformerException, IOException {
        LOG.info("--> BEGIN handleXrdsRequest");
        String xrds = getOpenIdProcessor().processXrdsRequest(info);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/xrds+xml;charset=utf-8");
        response.addHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.addHeader("Expires", "0");
        response.addHeader("Pragma", "no-cache");
        response.getWriter().println(xrds);
        LOG.info("--> END handleXrdsRequest");
    }

    public void handleAssociationRequest(String info, HttpServletResponse response, final ParameterList requestParameter) throws IOException {
        LOG.info("--> BEGIN handleAssociationRequest");
        Message openidResponse = getOpenIdProcessor().processAssociationRequest(requestParameter);
        String assocHandle = openidResponse.getParameterValue("assoc_handle");
        String shortLog = String.format("Association established: %s", assocHandle);
        String requestText = info + "\n\n" + requestParameter.toString();
        LOG.info(String.format("    --> assoc_handle = %s", assocHandle));
        response.setStatus(HttpServletResponse.SC_OK);
        String responseText = openidResponse.keyValueFormEncoding();
        response.getWriter().println(responseText);
        RequestLogger.getInstance().add(RequestType.ASSOCIATION, shortLog, requestText, responseText, idpType);
        LOG.info("--> END handleAssociationRequest");
    }

    public void handleTokenRequest(String info, HttpServletResponse response, final ParameterList requestParameter) throws IOException, OpenIdAttackerServerException {
        LOG.info("--> BEGIN handleTokenRequest");
        
        // check whether the association handle should be excluded from
        // Authentication Request => force direct authentication
        /*if (OpenIdServerConfiguration.getAttackerInstance().isRemoveAssocHandleFromAuthRequest()) {
            requestParameter.removeParameters("openid.assoc_handle");
        } */       
        
        // check settings for GET or POST redirect
        if (idpType.equals(IdpType.ANALYZER)) {
            if (OpenIdServerConfiguration.getAnalyzerInstance().isMethodGet()){
                handleTokenRequestwithGetRedirect(response, requestParameter);
            } else {
                handleTokenRequestWithPostRedirect(info, response, requestParameter);
            }
        } else {
            if (OpenIdServerConfiguration.getAttackerInstance().isMethodGet()){
                handleTokenRequestwithGetRedirect(response, requestParameter);
            } else {
                handleTokenRequestWithPostRedirect(info, response, requestParameter);
            }
        }
        
        LOG.info("--> END handleTokenRequest");
    }

    public void handleTokenRequestWithPostRedirect(String info, HttpServletResponse response, final ParameterList requestParameter) throws OpenIdAttackerServerException, IOException {
        String assoc_handle = requestParameter.getParameterValue("openid.assoc_handle");
        LOG.info(String.format("--> BEGIN handleTokenRequestwithGetRedirect for assoc_handle='%s'",
          assoc_handle != null ? assoc_handle : "<NONE>"));
        AttackParameterKeeper keeper = getOpenIdProcessor().processTokenRequest(requestParameter);
        response.setStatus(HttpServletResponse.SC_OK);
        String destinationUrl = getDestinationUrl(keeper);
        
        boolean performAttack;
        boolean interceptIdpResponse;
        if (idpType == IdpType.ATTACKER) {
            performAttack = OpenIdServerConfiguration.getAttackerInstance().isPerformAttack();
            interceptIdpResponse = OpenIdServerConfiguration.getAttackerInstance().isInterceptIdPResponse();
        } else {
            performAttack = OpenIdServerConfiguration.getAnalyzerInstance().isPerformAttack();
            interceptIdpResponse = OpenIdServerConfiguration.getAnalyzerInstance().isInterceptIdPResponse();
        }
        
        Map<String, String> getParameters = AttackParameterHandler.createMapByMethod(keeper, HttpMethod.GET, performAttack);
        Map<String, String> postParamters = AttackParameterHandler.createMapByMethod(keeper, HttpMethod.POST, performAttack);
        String postRedirectHtml = HttpPostRedirect.createPostRedirect(destinationUrl, getParameters, postParamters, interceptIdpResponse);
        response.getWriter().println(postRedirectHtml);

        RequestType type;
        if (performAttack) {
            type = RequestType.TOKEN_ATTACK;
        } else {
            type = RequestType.TOKEN_VALID;
        }
        String responseText = String.format("GET:\n\n%s\nPOST:\n\n%s", PrintHelper.mapToString(getParameters), PrintHelper.mapToString(postParamters));
        RequestLogger.getInstance().add(type, "Token generated", info + "\n\n" + requestParameter.toString(), responseText, idpType);
        LOG.info("--> END handleTokenRequestwithGetRedirect");
    }

    private String getDestinationUrl(AttackParameterKeeper keeper) {
        boolean performAttack = OpenIdServerConfiguration.getAttackerInstance().isPerformAttack();
        boolean toAttackUrl = OpenIdServerConfiguration.getAttackerInstance().isSendTokenToAttackUrl();
        
        if (idpType.equals(IdpType.ANALYZER)) {
            performAttack = OpenIdServerConfiguration.getAnalyzerInstance().isPerformAttack();
            toAttackUrl = OpenIdServerConfiguration.getAnalyzerInstance().isSendTokenToAttackUrl();
        }
        
        String destinationUrl;
        if (performAttack && toAttackUrl) {
            destinationUrl = keeper.getParameter("openid.return_to").getAttackValue();
        } else {
            destinationUrl = keeper.getParameter("openid.return_to").getValidValue();
        }
        return destinationUrl;
    }

    
    public void handleTokenRequestwithGetRedirect(HttpServletResponse response, final ParameterList requestParameter)
      throws OpenIdAttackerServerException {
        String assoc_handle = requestParameter.getParameterValue("openid.assoc_handle");
        LOG.info(String.format("--> BEGIN handleTokenRequestwithGetRedirect for assoc_handle='%s'",
          assoc_handle != null ? assoc_handle : "<NONE>"));
        AttackParameterKeeper keeper = openIdProcessor.processTokenRequest(requestParameter);
        response.setStatus(HttpServletResponse.SC_SEE_OTHER);
        
        boolean performAttack = false;
        if (idpType == IdpType.ATTACKER) {
            performAttack = OpenIdServerConfiguration.getAttackerInstance().isPerformAttack();
        } else {
            performAttack = OpenIdServerConfiguration.getAnalyzerInstance().isPerformAttack();
        }
        
        RequestType type;
        if (performAttack) {
            type = RequestType.TOKEN_ATTACK;
        } else {
            type = RequestType.TOKEN_VALID;
        }
        
        Map<String, String> getParameters = AttackParameterHandler.createMapByMethod(keeper, HttpMethod.GET, performAttack);
        String location = HttpPostRedirect.createGetRequest(getDestinationUrl(keeper), getParameters);
        
        response.setHeader("Location", location);
        String responseText = String.format("GET:\n\n%s", PrintHelper.mapToString(getParameters));
        RequestLogger.getInstance().add(type, "Token generated", requestParameter.toString(), responseText, idpType);
        
        LOG.info("--> END handleTokenRequestwithGetRedirect");
    }
    
    public void handleError(HttpServletResponse response, HttpServletRequest request, final String errorMessage, final int ERROR_CODE) throws IOException {
        LOG.info("--> BEGIN handleError");
        Message openidResponse = DirectError.createDirectError(errorMessage);
        response.setStatus(ERROR_CODE);
        response.setContentType("text/html;charset=utf-8");
        String responseText = openidResponse.keyValueFormEncoding();
        response.getWriter().println(responseText);
        String requestContent = String.format("%s %s\n\nParameters:\n\n%s",
          request.getMethod(),
          request.getRequestURL(),
          new ParameterList(request.getParameterMap()));
        RequestLogger.getInstance().add(RequestType.ERROR, errorMessage, requestContent, errorMessage, idpType);
        LOG.info("--> END handleError");
    }

    @Override
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            final Map<String, String[]> parameterMap = request.getParameterMap();
            final ParameterList parameterList = new ParameterList(parameterMap);
            handleRequest(parameterList, target, response, baseRequest);
        } catch (OpenIdAttackerServerException | TransformerException | IOException ex) {
            final String message = ex.getMessage();
            handleError(response, request, message, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } catch (IllegalStateException ex) {
            handleError(response, request, "Unknown request", HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } catch (IllegalArgumentException ex) {
            final String message = String.format("Argument Error: %s", ex.getMessage());
            handleError(response, request, message, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } catch (Exception ex) {
            final String message = String.format("Unknown request: %s", ex.getMessage());
            handleError(response, request, message, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    public CustomOpenIdProcessor getOpenIdProcessor() {
        return openIdProcessor;
    }

    public void setOpenIdProcessor(CustomOpenIdProcessor openIdProcessor) {
        CustomOpenIdProcessor oldOpenIdProcessor = this.openIdProcessor;
        this.openIdProcessor = openIdProcessor;
        propertyChangeSupport.firePropertyChange(PROP_OPENIDPROCESSOR, oldOpenIdProcessor, openIdProcessor);
    }

    private void handleRequest(ParameterList requestParameter, String target, HttpServletResponse response, Request baseRequest) throws IOException, OpenIdAttackerServerException, TransformerException {
        // get the openIdProcessor.mode
        final String method = baseRequest.getMethod();
        final HttpURI uri = baseRequest.getUri();
        final String protocol = baseRequest.getProtocol();
        final String info = String.format("%s %s %s", method, uri, protocol);
        final String mode = requestParameter.hasParameter("openid.mode")
          ? requestParameter.getParameterValue("openid.mode") : null;

	if (uri.getCompletePath().equals("/favicon.ico")) {
            handleFaviconRequest(info, response);
        } else if (target.contains("xxe")) {
            // Case: XXE
            handleXxeRequest(info, response, requestParameter);
        } /*else if (target.contains("dtd")) {
            // Case: DTD
            handleDtdRequest(info, response, requestParameter);
        }*/ else if (mode == null) {
            if (target.contains("xrds") || requestParameter.toString().contains("xrds")) {
                // Case: Request XRDS Document
                handleXrdsRequest(info, response);                
            } else {
                // Case: Request HTML Document
                handleHtmlDiscovery(info, response);
            }
        } else if ("associate".equals(mode)) {
            // Case: Process Association
            handleAssociationRequest(info, response, requestParameter);
        } else if ("checkid_setup".equals(mode) || "checkid_immediate".equals(mode)) {
            // Case: Generate Token
            handleTokenRequest(info, response, requestParameter);
        } else if ("check_authentication".equals(mode)) {
            handleCheckAuthentication(info, response, requestParameter);
        } else {
            throw new IllegalStateException("Unknown Request");
        }
        baseRequest.setHandled(true);
    }
    
    private void handleXxeRequest(String info, HttpServletResponse response, final ParameterList requestParameter) throws IOException {
        LOG.info("--> BEGIN handleXxeRequest");
        String requestText = String.format("%s\n\n%s", info, requestParameter.toString());
        response.setStatus(HttpServletResponse.SC_OK);
        String responseText = "http://rub.de";
        response.getWriter().print(responseText);
        RequestLogger.getInstance().add(RequestType.XXE, "XXE", requestText, responseText, idpType);
        LOG.info("--> END handleXxeRequest");
    }
    
    /*private void handleDtdRequest(String info, HttpServletResponse response, final ParameterList requestParameter) throws IOException {
        LOG.info("--> BEGIN handleDtdRequest");
        String requestText = String.format("%s\n\n%s", info, requestParameter.toString());
        response.setStatus(HttpServletResponse.SC_OK);
        String responseText = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                              "<!ENTITY % xxe SYSTEM \"http://my-idp.info/xxe\">\n" +
                              "%xxe;";
        response.getWriter().println(responseText);
        System.out.println("dtd");
        //RequestLogger.getAttackerInstance().add(RequestType.XXE, "XXE", requestText, responseText);
        LOG.info("--> END handleDtdRequest");
    }*/

    private void handleCheckAuthentication(String info, HttpServletResponse response, final ParameterList requestParameter) throws IOException {

        LOG.info("--> BEGIN handleCheckAuthentication");
        String assocHandle = requestParameter.getParameterValue("openid.assoc_handle");
        String shortLog = String.format("Returning check_authentication = true for %s", assocHandle);
        LOG.info(String.format("    --> assoc_handle = %s", assocHandle));
        
        Message responseMessage;
        if (idpType.equals(IdpType.ATTACKER)) {
            responseMessage = getOpenIdProcessor().generatePositiveCheckAuthenticationResponse();
        } else {
            responseMessage = getOpenIdProcessor().generateCorrectCheckAuthenticationResponse(requestParameter);
        }
        String responseText = responseMessage.keyValueFormEncoding();
        response.getWriter().println(responseText);
        response.setStatus(HttpServletResponse.SC_OK);
        String requestText = String.format("%s\n\n%s", info, requestParameter.toString());
        RequestLogger.getInstance().add(RequestType.CHECK_AUTHENTICATION, shortLog, requestText, responseText, idpType);
        LOG.info("--> END handleCheckAuthentication");
    }

    private void handleHtmlDiscovery(String info, HttpServletResponse response) throws IOException {
        LOG.info("--> BEGIN handleHtmlDiscovery");
        final CustomOpenIdProcessor p = getOpenIdProcessor();
        final String xrds = p.processHtmlDiscoveryRequest(info);
        final HtmlDiscoveryConfiguration htmlConfiguration = p.getHtmlConfiguration();
        if (htmlConfiguration.isIncludeXrdsHttpHeader()) {
            final String identity = htmlConfiguration.getIdentity();
            response.addHeader("X-XRDS-Location", identity + "?xrds");
        }
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/html;charset=utf-8");
        response.addHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.addHeader("Expires", "0");
        response.addHeader("Pragma", "no-cache");
        response.getWriter().println(xrds);
        LOG.info("--> END handleHtmlDiscovery");
    }

    private void handleFaviconRequest(String info, HttpServletResponse response) {
        LOG.info("--> BEGIN handleFaviconRequest");
        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
//        response.setContentType("text/html;charset=utf-8");
        LOG.info("--> END handleFaviconRequest");
    }
}
