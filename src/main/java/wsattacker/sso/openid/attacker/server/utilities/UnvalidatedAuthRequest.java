package wsattacker.sso.openid.attacker.server.utilities;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.MessageException;
import org.openid4java.message.ParameterList;
import org.openid4java.server.RealmVerifier;

public class UnvalidatedAuthRequest extends AuthRequest {

    private static final Log LOG = LogFactory.getLog(UnvalidatedAuthRequest.class);
    private static final boolean DEBUG = LOG.isDebugEnabled();

    protected UnvalidatedAuthRequest(ParameterList params) {
        super(params);
    }

    public static AuthRequest createAuthRequest(ParameterList params,
      RealmVerifier realmVerifier)
      throws MessageException {
        AuthRequest req = new UnvalidatedAuthRequest(params);

        req.setRealmVerifier(realmVerifier);

        // The request must not be validated
        // req.validate();
        if (DEBUG) {
            LOG.debug("Created auth request:\n" + req.keyValueFormEncoding());
        }

        return req;
    }
}
