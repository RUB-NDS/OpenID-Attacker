package wsattacker.sso.openid.attacker.config;

import org.apache.log4j.Logger;

/**
 * Exception which will be thrown in the error case when loading or saving
 * a config XML file.
 */
public class XmlPersistenceError extends Exception {

    private static final Logger LOG = Logger.getLogger(XmlPersistenceError.class);

    public XmlPersistenceError(String message) {
        super(message);
        LOG.warn(message);
    }

    public XmlPersistenceError(String message, Throwable cause) {
        super(message, cause);
        LOG.warn(message);
    }

    public XmlPersistenceError(Throwable cause) {
        super(cause);
        LOG.warn(cause);
    }
}
