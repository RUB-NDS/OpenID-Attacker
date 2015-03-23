package wsattacker.sso.openid.attacker.discovery.exception;

public class DiscoveryException extends RuntimeException {

    /**
     * Creates a new instance of
     * <code>DiscoveryException</code> without detail message.
     */
    public DiscoveryException(String msg, Throwable e) {
        super(msg, e);
    }

    /**
     * Constructs an instance of
     * <code>DiscoveryException</code> with the specified detail message.
     *
     * @param msg the detail message.
     */
    public DiscoveryException(String msg) {
        super(msg);
    }
}
