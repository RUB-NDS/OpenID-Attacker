package wsattacker.sso.openid.attacker.server;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.jetty.server.Server;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameterHandler;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameterKeeper;
import wsattacker.sso.openid.attacker.composition.AbstractBean;
import wsattacker.sso.openid.attacker.config.OpenIdServerConfiguration;
import wsattacker.sso.openid.attacker.discovery.html.HtmlDiscoveryConfiguration;
import wsattacker.sso.openid.attacker.discovery.xrds.XrdsConfiguration;
import wsattacker.sso.openid.attacker.server.buisinesslogic.CustomInMemoryServerAssociationStore;
import wsattacker.sso.openid.attacker.server.buisinesslogic.CustomOpenIdProcessor;
import wsattacker.sso.openid.attacker.server.buisinesslogic.CustomOpenIdProviderHandler;
import wsattacker.sso.openid.attacker.server.exception.OpenIdAttackerServerException;
import wsattacker.sso.openid.attacker.server.status.Status;
import wsattacker.sso.openid.attacker.user.User;

public class OpenIdServer extends AbstractBean implements PropertyChangeListener {

    private static final Log LOG = LogFactory.getLog(OpenIdServer.class);
    public static final String PROP_STATUS = "status";
    public static final String PROP_STOREDASSOCIATIONS = "storedAssociations";
    //public static final String PROP_PROCESSOR = "processor";
    public static final String PROP_HANDLER = "handler";
    public static final String PROP_STORE = "store";
    private Status status = Status.STOPPED;
    private Server newServer = null;
    private CustomOpenIdProcessor processor;
    private CustomOpenIdProviderHandler handler;
    private CustomInMemoryServerAssociationStore store;
    private OpenIdServerConfiguration config;
    private String serverStatusline = status.toString();
    public static final String PROP_SERVERSTATUSLINE = "serverStatusline";

    /**
     * Get the value of serverStatusline
     *
     * @return the value of serverStatusline
     */
    public String getServerStatusline() {
        return serverStatusline;
    }

    public CustomInMemoryServerAssociationStore getStore() {
        return store;
    }

    /**
     * Set the value of serverStatusline
     *
     * @param serverStatusline new value of serverStatusline
     */
    private void setServerStatusline(String serverStatusline) {
        String oldServerStatusline = this.serverStatusline;
        this.serverStatusline = serverStatusline;
        firePropertyChange(PROP_SERVERSTATUSLINE, oldServerStatusline, serverStatusline);
    }

    public OpenIdServer() {
        this(IdpType.ATTACKER);
    }
    
    public OpenIdServer(IdpType idpType) {
        
        switch (idpType) {
            case ATTACKER:
                this.config = OpenIdServerConfiguration.getAttackerInstance();
                break;
            case ANALYZER:
                this.config = OpenIdServerConfiguration.getAnalyzerInstance();
                break;
        }
        
        final XrdsConfiguration xrdsConfig = config.getXrdsConfiguration();
        final HtmlDiscoveryConfiguration htmlConfiguration = config.getHtmlConfiguration();
        handler = new CustomOpenIdProviderHandler(idpType);
        processor = handler.getOpenIdProcessor();
        processor.setEndpoint(xrdsConfig.getBaseUrl());
        processor.setExpiresIn(config.getAssociationExpirationInSeconds());
        processor.setValidUser(config.getValidUser());
        processor.setXrdsConfiguration(xrdsConfig);
        processor.setHtmlConfiguration(htmlConfiguration);
        store = new CustomInMemoryServerAssociationStore();
        processor.setStore(store);
        store.setAssociationPrefix(config.getAssociationPrefix());
        config.addPropertyChangeListener(this);
        xrdsConfig.addPropertyChangeListener(this);
    }

    @Override
    public void propertyChange(PropertyChangeEvent pce) {
        String propertyName = pce.getPropertyName();
        Object newValue = pce.getNewValue();
        Object oldValue = pce.getOldValue();
        switch (propertyName) {
            case OpenIdServerConfiguration.PROP_HTMLCONFIGURATION:
                HtmlDiscoveryConfiguration oldHtmlConfig = (HtmlDiscoveryConfiguration) oldValue;
                HtmlDiscoveryConfiguration newHtmlConfig = (HtmlDiscoveryConfiguration) newValue;
                LOG.info("Changed HTML Discovery Configuration");
                oldHtmlConfig.removePropertyChangeListener(this);
                newHtmlConfig.addPropertyChangeListener(this);
                processor.setHtmlConfiguration(newHtmlConfig);
                break;
            case OpenIdServerConfiguration.PROP_XRDSCONFIGURATION:
                XrdsConfiguration oldConfig = (XrdsConfiguration) oldValue;
                XrdsConfiguration newConfig = (XrdsConfiguration) newValue;
                LOG.info("Changed XRDS Configuration");
                oldConfig.removePropertyChangeListener(this);
                newConfig.addPropertyChangeListener(this);
                processor.setXrdsConfiguration(newConfig);
                processor.setEndpoint(newConfig.getBaseUrl());
                break;
            case XrdsConfiguration.PROP_BASEURL:
                LOG.info(String.format("Changed Endpoint URI from '%s' to '%s'", oldValue, newValue));
                processor.setEndpoint((String) pce.getNewValue());
                break;
            case OpenIdServerConfiguration.PROP_ASSOCIATIONEXPIRATIONINSECONDS:
                LOG.info(String.format("Changed Association expiration time from %ss to %ss", oldValue, newValue));
                processor.setExpiresIn((int) pce.getNewValue());
                break;
            case OpenIdServerConfiguration.PROP_VALIDUSER:
                LOG.info("Changed valid user!");
                processor.setValidUser((User) newValue);
                break;
            case OpenIdServerConfiguration.PROP_ASSOCIATIONPREFIX:
                LOG.info(String.format("Association Prefix changed from '%s' to '%s'", oldValue, newValue));
                store.setAssociationPrefix((String) newValue);
                break;
            default:
                break;
        }
    }

    public void removeParameter(String name) {
        processor.getKeeper().removeParameter(name);
    }

    public void addParameter(String name) {
        AttackParameterHandler.addCustomParameter(processor.getKeeper(), name);
    }

    public void clearParameters() {
        processor.getKeeper().clear();
    }

    public Status getStatus() {
        return status;
    }

    public void stop() throws OpenIdAttackerServerException {
        if (newServer == null || status.equals(Status.STOPPED)) {
            throw new OpenIdAttackerServerException("Server is not running");
        }
        try {
            newServer.stop();
            Status oldStatus = status;
            status = Status.STOPPED;
            setServerStatusline(status.toString());
            firePropertyChange(PROP_STATUS, oldStatus, status);
        } catch (Exception ex) {
            throw new OpenIdAttackerServerException("Could not stop the server", ex);
        }
    }

    public void start() throws OpenIdAttackerServerException {
        int port = config.getServerListenPort();
        newServer = new Server(port);
        newServer.setHandler(handler);
        try {
            newServer.start();
            Status oldStatus = status;
            status = Status.RUNNING;
            setServerStatusline(String.format("%s... URL: %s Port: %d", status, processor.getEndpoint(), port));
            firePropertyChange(PROP_STATUS, oldStatus, status);
        } catch (Exception ex) {
            throw new OpenIdAttackerServerException("Could not start the server", ex);
        }
    }

    public AttackParameterKeeper getParameterConfiguration() {
        return processor.getKeeper();
    }
}