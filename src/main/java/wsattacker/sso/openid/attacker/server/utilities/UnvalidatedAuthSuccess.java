package wsattacker.sso.openid.attacker.server.utilities;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.MessageException;
import org.openid4java.message.ParameterList;

public class UnvalidatedAuthSuccess extends AuthSuccess {

    private static final Log LOG = LogFactory.getLog(UnvalidatedAuthSuccess.class);
    private static final boolean DEBUG = LOG.isDebugEnabled();

    protected UnvalidatedAuthSuccess(ParameterList params) {
        super(params);
    }

    public static AuthSuccess createAuthSuccess(ParameterList params)
      throws MessageException {
        AuthSuccess resp = new UnvalidatedAuthSuccess(params);

        // The response token must not be validated
        // This allows e.g. to create signed tokens WITHOUT claimed_id etc.
        // resp.validate();
        if (DEBUG) {
            LOG.debug("Created positive auth response:\n"
              + resp.keyValueFormEncoding());
        }

        return resp;
    }
}
