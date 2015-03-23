package wsattacker.sso.openid.attacker.server.buisinesslogic;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.xml.transform.TransformerException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openid4java.association.AssociationException;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.Message;
import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.Parameter;
import org.openid4java.message.ParameterList;
import org.openid4java.message.VerifyResponse;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.sreg.SRegMessage;
import org.openid4java.message.sreg.SRegRequest;
import org.openid4java.message.sreg.SRegResponse;
import org.openid4java.server.ServerAssociationStore;
import org.openid4java.server.ServerException;
import org.openid4java.server.ServerManager;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameter;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameterHandler;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameterKeeper;
import wsattacker.sso.openid.attacker.composition.AbstractBean;
import wsattacker.sso.openid.attacker.discovery.html.HtmlDiscoveryConfiguration;
import wsattacker.sso.openid.attacker.discovery.xrds.OpenIdVersion;
import wsattacker.sso.openid.attacker.discovery.xrds.XrdsConfiguration;
import wsattacker.sso.openid.attacker.log.RequestLogger;
import wsattacker.sso.openid.attacker.log.RequestType;
import wsattacker.sso.openid.attacker.server.exception.OpenIdAttackerServerException;
import wsattacker.sso.openid.attacker.server.utilities.UnvalidatedAuthRequest;
import wsattacker.sso.openid.attacker.server.utilities.UnvalidatedAuthSuccess;
import wsattacker.sso.openid.attacker.user.User;

/**
 * Processer which hold the buisiness logic for OpenId requests.
 */
public class CustomOpenIdProcessor extends AbstractBean {

	public static final String PROP_STORE = "store";
	public static final String PROP_VALIDUSER = "validUser";
	public static final String PROP_KEEPER = "keeper";
	public static final String PROP_EXPIRESIN = "expiresIn";
	public static final String PROP_ENDPOINT = "endpoint";
	public static final String PROP_XRDSCONFIGURATION = "xrdsConfiguration";
	private static final Log LOG = LogFactory.getLog(CustomOpenIdProcessor.class);
	private ServerManager serverManager = new ServerManager();
	private User validUser = new User();
	private AttackParameterKeeper keeper = new AttackParameterKeeper();
	private XrdsConfiguration xrdsConfiguration = new XrdsConfiguration();
	private HtmlDiscoveryConfiguration htmlConfiguration = new HtmlDiscoveryConfiguration();

	public CustomOpenIdProcessor() {
		// for a working demo, not enforcing RP realm discovery
		// since this new feature is not deployed
		serverManager.getRealmVerifier().setEnforceRpId(false);
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
		this.htmlConfiguration = htmlConfiguration;
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
	 * Get the value of expiresIn
	 *
	 * @return the value of expiresIn
	 */
	public int getExpiresIn() {
		return serverManager.getExpireIn();
	}

	/**
	 * Set the value of expiresIn
	 *
	 * @param expiresIn new value of expiresIn
	 */
	public void setExpiresIn(int expiresIn) {
		int oldExpiresIn = getExpiresIn();
		serverManager.setExpireIn(expiresIn);
		firePropertyChange(PROP_EXPIRESIN, oldExpiresIn, expiresIn);
	}

	/**
	 * Get the value of endpoint
	 *
	 * @return the value of endpoint
	 */
	public String getEndpoint() {
		return serverManager.getOPEndpointUrl();
	}

	/**
	 * Set the value of endpoint
	 *
	 * @param endpoint new value of endpoint
	 */
	public void setEndpoint(String endpoint) {
		String oldEndpoint = getEndpoint();
		serverManager.setOPEndpointUrl(endpoint);
		firePropertyChange(PROP_ENDPOINT, oldEndpoint, endpoint);
	}

	/**
	 * Generates an XRDS Document for the current validUser.
	 *
	 * @return XRDS Document as a String
	 *
	 * @throws TransformerException
	 */
	public String processXrdsRequest(String info) throws TransformerException {
		final String identity = xrdsConfiguration.getIdentity();
		final OpenIdVersion version = xrdsConfiguration.getOpenIdVersion();
		final String xrds = xrdsConfiguration.getXml();
		final String shortLog = String.format("Requested XRDS Document for '%s' with %s", identity, version);
		RequestLogger.getInstance().add(RequestType.XRDS, shortLog, info + "\n\nXRDS Request", xrds);
		return xrds;
	}

	/**
	 * Generates an Association. Uses DHKE.
	 *
	 * @param assoc_parameter
	 *
	 * @return
	 */
	public Message processAssociationRequest(final ParameterList assoc_parameter) {
		return serverManager.associationResponse(assoc_parameter);
	}

	/**
	 * Creates an OpenID Token. Depending of the global config, either a
	 * token for the valid user or for the attacker is created.
	 *
	 * @param token_parameter
	 *
	 * @return
	 *
	 * @throws MessageException
	 * @throws ServerException
	 * @throws AssociationException
	 */
	public AttackParameterKeeper processTokenRequest(final ParameterList token_parameter) throws OpenIdAttackerServerException {
		addNamespaceIfNotContained(token_parameter);
		AuthRequest authRequest = createAuthenticationRequest(token_parameter);
		return processTokenRequest(authRequest);
	}

	/**
	 * Returns the currently used ServerAssociationStore.
	 *
	 * @return
	 */
	public ServerAssociationStore getStore() {
		return serverManager.getSharedAssociations();
	}

	/**
	 * Sets the ServerAssociationStore.
	 *
	 * @param store
	 */
	public void setStore(ServerAssociationStore store) {
		ServerAssociationStore oldStore = getStore();
		serverManager.setSharedAssociations(store);
		firePropertyChange(PROP_STORE, oldStore, store);
	}

	public User getValidUser() {
		return validUser;
	}

	public void setValidUser(User validUser) {
		wsattacker.sso.openid.attacker.user.User oldValidUser = this.validUser;
		this.validUser = validUser;
		firePropertyChange(PROP_VALIDUSER, oldValidUser, validUser);
	}

	public AttackParameterKeeper getKeeper() {
		return keeper;
	}

	public Message generatePositiveCheckAuthenticationResponse() {
		HashMap<String, String> result = new LinkedHashMap<>();
		result.put("ns", "http://specs.openid.net/auth/2.0");
		result.put("is_valid", "true");
		ParameterList responseParameters = new ParameterList(result);
		try {
			Message m = VerifyResponse.createVerifyResponse(responseParameters);
			return m;
		} catch (MessageException ex) {
			throw new IllegalStateException("This should never happen", ex);
		}
	}

	public String processHtmlDiscoveryRequest(String info) {
		final String identity = htmlConfiguration.getIdentity();
		final boolean openid1 = htmlConfiguration.isOpenidServer();
		final boolean openid2 = htmlConfiguration.isOpenId2Provider();
		final boolean includeIdentity = htmlConfiguration.isIncludeIdentity();
		final String html = htmlConfiguration.getHtml();
		final String shortLog = String.format("Requested HTML Document for '%s'. (Version1: %b / Version2: %b / Include Identity: %b)", identity, openid1, openid2, includeIdentity);
		RequestLogger.getInstance().add(RequestType.HTML, shortLog, info + "\n\nHTML Request", html);
		return html;
	}

	/**
	 * Creates an OpenID Token. Depending of the global config, either a
	 * token for the valid user or for the attacker is created.
	 *
	 * @param authRequest
	 *
	 * @return
	 *
	 * @throws MessageException
	 * @throws ServerException
	 * @throws AssociationException
	 */
	private AttackParameterKeeper processTokenRequest(final AuthRequest authRequest) throws OpenIdAttackerServerException {
		final String userSelId = getValidUser().getIdentifier();
		final String userSelClaimed = getValidUser().getClaimedId();
		final Message token = serverManager.authResponse(authRequest, userSelId, userSelClaimed, true, false);
		if (token instanceof AuthSuccess) {
			try {
				processAxExtension(token, authRequest);
				processSRegExtension(token, authRequest);
				generateSignatureForValidValues((AuthSuccess) token);
				generateSignatureForAttackValues();
			} catch (ServerException | MessageException | AssociationException ex) {
				throw new OpenIdAttackerServerException(ex.getMessage());
			}
		} else {
			throw new OpenIdAttackerServerException("Error while creating auth Response");
		}
		return getKeeper();
	}

	private void setKeeper(AttackParameterKeeper keeper) {
		wsattacker.sso.openid.attacker.attack.parameter.AttackParameterKeeper oldKeeper = this.keeper;
		this.keeper = keeper;
		firePropertyChange(PROP_KEEPER, oldKeeper, keeper);
	}

	private Message processAxExtension(Message token, final AuthRequest authRequest) throws MessageException {
		if (authRequest.hasExtension(AxMessage.OPENID_NS_AX)) {
			MessageExtension extension = authRequest.getExtension(AxMessage.OPENID_NS_AX);
			if (extension instanceof FetchRequest) {
				final FetchRequest fetchRequest = (FetchRequest) extension;
				final Map userDataMap = getValidUser().getUserDataMap();
				final FetchResponse fetchResponse = FetchResponse.createFetchResponse(fetchRequest, userDataMap);
				token.addExtension(fetchResponse, "ax");
			} else {
				throw new UnsupportedOperationException("TODO: if (ext instanceof StoreRequest)");
			}
		}
		return token;
	}

	private Message processSRegExtension(Message token, final AuthRequest authRequest) throws MessageException {
		String sregNamespace = detectSRegVersion(authRequest);
		if (sregNamespace != null) {
			MessageExtension ext = authRequest.getExtension(sregNamespace);
			if (ext instanceof SRegRequest) {
				SRegRequest sregReq = (SRegRequest) ext;
				SRegResponse sregResp = SRegResponse.createSRegResponse(sregReq, getValidUser().getUserDataMap());
				token.addExtension(sregResp, "sreg");
			} else if (ext instanceof SRegResponse) {
				// what to do here?
			} else {
				final String message = String.format("TODO - Support of '%s'", ext.getClass().getCanonicalName());
				throw new UnsupportedOperationException(message);
			}
		}
		return token;
	}

	private void generateSignatureForValidValues(AuthSuccess token) throws AssociationException, ServerException {
		serverManager.sign(token);
		AttackParameterHandler.updateValidParameters(getKeeper(), token.getParameterMap());
	}

	private void generateSignatureForAttackValues() throws AssociationException, MessageException, ServerException {
		AttackParameter signature = getKeeper().getParameter("openid.sig");
		// only compute sig if no custom value is specified
		if (signature != null && !signature.isAttackValueUsedForSignatureComputation()) {
			Map<String, String> currentAttackMap = AttackParameterHandler.createToSignMap(getKeeper());
			ParameterList pl = new ParameterList(currentAttackMap);
			AuthSuccess success = UnvalidatedAuthSuccess.createAuthSuccess(pl);
			serverManager.sign(success);
			AttackParameterHandler.updateAttackParameters(getKeeper(), success.getParameterMap());
		}
	}

	private void addNamespaceIfNotContained(ParameterList token_parameter) {
		if (!token_parameter.hasParameter("ns")) {
			final String nsValue = xrdsConfiguration.getOpenIdVersion().getNS();
			final Parameter nsParameter = new Parameter("openid.ns", nsValue);
			token_parameter.set(nsParameter);
		}
	}

	private AuthRequest createAuthenticationRequest(final ParameterList token_parameter) throws OpenIdAttackerServerException {
		AuthRequest authRequest;
		try {
//            authRequest = AuthRequest.createAuthRequest(token_parameter, serverManager.getRealmVerifier());
			authRequest = UnvalidatedAuthRequest.createAuthRequest(token_parameter, serverManager.getRealmVerifier());
		} catch (MessageException ex) {
			throw new OpenIdAttackerServerException(ex);
		}
		return authRequest;
	}

	private String detectSRegVersion(final AuthRequest authRequest) {
		String sregNamespace = null;
		if (authRequest.hasExtension(SRegMessage.OPENID_NS_SREG)) {
			sregNamespace = SRegMessage.OPENID_NS_SREG;
		} else if (authRequest.hasExtension(SRegMessage.OPENID_NS_SREG11)) {
			sregNamespace = SRegMessage.OPENID_NS_SREG11;
		}
		return sregNamespace;
	}

	/**
	 * This is just needed for testing
	 *
	 * @return
	 */
	protected ServerManager getServerManager() {
		return serverManager;
	}
}
