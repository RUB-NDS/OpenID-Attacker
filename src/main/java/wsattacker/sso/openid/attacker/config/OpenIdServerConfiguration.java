package wsattacker.sso.openid.attacker.config;

import java.io.Serializable;
import java.util.Date;
import javax.xml.bind.annotation.XmlRootElement;
import wsattacker.sso.openid.attacker.attack.profile.AttackProfileContainer;
import wsattacker.sso.openid.attacker.composition.AbstractBean;
import wsattacker.sso.openid.attacker.discovery.html.HtmlDiscoveryConfiguration;
import wsattacker.sso.openid.attacker.discovery.xrds.XrdsConfiguration;
import wsattacker.sso.openid.attacker.user.User;
import wsattacker.sso.openid.attacker.user.UserDataCollector;

@XmlRootElement(name = "OpenIdConfiguration")
public final class OpenIdServerConfiguration extends AbstractBean implements Serializable {

    public static final String PROP_INTERCEPTIDPRESPONSE = "interceptIdPResponse";
    public static final String PROP_SERVERLISTENPORT = "serverListenPort";
    public static final String PROP_ASSOCIATIONEXPIRATIONINSECONDS = "associationExpirationInSeconds";
    public static final String PROP_PERFORMATTACK = "performAttack";
    public static final String PROP_ASSOCIATIONPREFIX = "associationPrefix";
    public static final String PROP_VALIDUSER = "validUser";
    public static final String PROP_ATTACKDATA = "attackData";
    public static final String PROP_PROFILES = "profiles";
    public static final String PROP_XRDSCONFIGURATION = "xrdsConfiguration";
    public static final String PROP_HTMLCONFIGURATION = "htmlConfiguration";

    public static final String PROP_SENDTOKENTOATTACKURL = "sendTokenToAttackUrl";

    private static final OpenIdServerConfiguration INSTANCE = new OpenIdServerConfiguration();

    /**
     * Singleton Method to get the Configuration.
     *
     * @return a Configuration for the OpenID Attacker
     */
    public static OpenIdServerConfiguration getInstance() {
        return INSTANCE;
    }

    private boolean sendTokenToAttackUrl = false;
    private HtmlDiscoveryConfiguration htmlConfiguration = new HtmlDiscoveryConfiguration();
    private XrdsConfiguration xrdsConfiguration = new XrdsConfiguration();
    private UserDataCollector attackData = new UserDataCollector();
    private String associationPrefix = Long.toString(new Date().getTime());
    private int serverListenPort = 8080;
    private boolean interceptIdPResponse = true;
    private boolean performAttack = false;
    private int associationExpirationInSeconds = 10;
    private User validUser = new User();
    private AttackProfileContainer profiles = new AttackProfileContainer();

    public OpenIdServerConfiguration() {
    }

    public boolean isSendTokenToAttackUrl() {
        return sendTokenToAttackUrl;
    }

    public void setSendTokenToAttackUrl(boolean sendTokenToAttackUrl) {
        boolean oldSendTokenToAttackUrl = this.sendTokenToAttackUrl;
        this.sendTokenToAttackUrl = sendTokenToAttackUrl;
        firePropertyChange(PROP_SENDTOKENTOATTACKURL, oldSendTokenToAttackUrl, sendTokenToAttackUrl);
    }

    /**
     * Get the value of htmlConfiguration
     *
     * @return the value of htmlConfiguration
     */
    public HtmlDiscoveryConfiguration getHtmlConfiguration() {
        return htmlConfiguration;
    }

    /**
     * Set the value of htmlConfiguration
     *
     * @param htmlConfiguration new value of htmlConfiguration
     */
    public void setHtmlConfiguration(HtmlDiscoveryConfiguration htmlConfiguration) {
        HtmlDiscoveryConfiguration oldHtmlConfiguration = this.htmlConfiguration;
        this.htmlConfiguration = htmlConfiguration;
        firePropertyChange(PROP_HTMLCONFIGURATION, oldHtmlConfiguration, htmlConfiguration);
    }

    /**
     * Get the value of xrdsConfiguration
     *
     * @return the value of xrdsConfiguration
     */
    public XrdsConfiguration getXrdsConfiguration() {
        return xrdsConfiguration;
    }

    /**
     * Set the value of xrdsConfiguration
     *
     * @param xrdsConfiguration new value of xrdsConfiguration
     */
    public void setXrdsConfiguration(XrdsConfiguration xrdsConfiguration) {
        XrdsConfiguration oldXrdsConfiguration = this.xrdsConfiguration;
        this.xrdsConfiguration = xrdsConfiguration;
        firePropertyChange(PROP_XRDSCONFIGURATION, oldXrdsConfiguration, xrdsConfiguration);
    }

    /**
     * Get the value of profiles
     *
     * @return the value of profiles
     */
    public AttackProfileContainer getProfiles() {
        return profiles;
    }

    /**
     * Set the value of profiles
     *
     * @param profiles new value of profiles
     */
    public void setProfiles(AttackProfileContainer profiles) {
        AttackProfileContainer oldProfiles = this.profiles;
        this.profiles = profiles;
        firePropertyChange(PROP_PROFILES, oldProfiles, profiles);
    }

    /**
     * Get the value of attackData
     *
     * @return the value of attackData
     */
    public UserDataCollector getAttackData() {
        return attackData;
    }

    /**
     * Set the value of attackData
     *
     * @param attackData new value of attackData
     */
    public void setAttackData(UserDataCollector attackData) {
        UserDataCollector oldAttackData = this.attackData;
        this.attackData = attackData;
        firePropertyChange(PROP_ATTACKDATA, oldAttackData, attackData);
    }

    /**
     * Get the value of validUser
     *
     * @return the value of validUser
     */
    public User getValidUser() {
        return validUser;
    }

    /**
     * Set the value of validUser
     *
     * @param validUser new value of validUser
     */
    public void setValidUser(User validUser) {
        User oldValidUser = this.validUser;
        this.validUser = validUser;
        firePropertyChange(PROP_VALIDUSER, oldValidUser, validUser);
    }

    /**
     * Get the value of associationPrefix
     *
     * @return the value of associationPrefix
     */
    public String getAssociationPrefix() {
        return associationPrefix;
    }

    /**
     * Set the value of associationPrefix
     *
     * @param associationPrefix new value of associationPrefix
     */
    public void setAssociationPrefix(String associationPrefix) {
        String oldAssociationPrefix = this.associationPrefix;
        this.associationPrefix = associationPrefix;
        firePropertyChange(PROP_ASSOCIATIONPREFIX, oldAssociationPrefix, associationPrefix);
    }

    /**
     * Get the value of performAttack
     *
     * @return the value of performAttack
     */
    public boolean isPerformAttack() {
        return performAttack;
    }

    /**
     * Set the value of performAttack
     *
     * @param performAttack new value of performAttack
     */
    public void setPerformAttack(boolean performAttack) {
        boolean oldPerformAttack = this.performAttack;
        this.performAttack = performAttack;
        firePropertyChange(PROP_PERFORMATTACK, oldPerformAttack, performAttack);
    }

    /**
     * Get the value of associationExpirationInSeconds
     *
     * @return the value of associationExpirationInSeconds
     */
    public int getAssociationExpirationInSeconds() {
        return associationExpirationInSeconds;
    }

    /**
     * Set the value of associationExpirationInSeconds
     *
     * @param associationExpirationInSeconds new value of
     *                                       associationExpirationInSeconds
     */
    public void setAssociationExpirationInSeconds(int associationExpirationInSeconds) {
        int oldAssociationExpirationInSeconds = this.associationExpirationInSeconds;
        this.associationExpirationInSeconds = associationExpirationInSeconds;
        firePropertyChange(PROP_ASSOCIATIONEXPIRATIONINSECONDS, oldAssociationExpirationInSeconds, associationExpirationInSeconds);
    }

    /**
     * Get the value of serverListenPort
     *
     * @return the value of serverListenPort
     */
    public int getServerListenPort() {
        return serverListenPort;
    }

    /**
     * Set the value of serverListenPort
     *
     * @param serverListenPort new value of serverListenPort
     */
    public void setServerListenPort(int serverListenPort) {
        int oldServerListenPort = this.serverListenPort;
        this.serverListenPort = serverListenPort;
        firePropertyChange(PROP_SERVERLISTENPORT, oldServerListenPort, serverListenPort);
    }

    /**
     * Get the value of interceptIdPResponse
     *
     * @return the value of interceptIdPResponse
     */
    public boolean isInterceptIdPResponse() {
        return interceptIdPResponse;
    }

    /**
     * Set the value of interceptIdPResponse
     *
     * @param interceptIdPResponse new value of interceptIdPResponse
     */
    public void setInterceptIdPResponse(boolean interceptIdPResponse) {
        boolean oldInterceptIdPResponse = this.interceptIdPResponse;
        this.interceptIdPResponse = interceptIdPResponse;
        firePropertyChange(PROP_INTERCEPTIDPRESPONSE, oldInterceptIdPResponse, interceptIdPResponse);
    }
}
