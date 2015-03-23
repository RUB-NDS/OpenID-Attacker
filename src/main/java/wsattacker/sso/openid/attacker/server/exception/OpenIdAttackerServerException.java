package wsattacker.sso.openid.attacker.server.exception;

public class OpenIdAttackerServerException extends Exception {

    public OpenIdAttackerServerException() {
    }

    public OpenIdAttackerServerException(String msg) {
        super(msg);
    }

    public OpenIdAttackerServerException(String msg, Throwable e) {
        super(msg, e);
    }

    public OpenIdAttackerServerException(Throwable cause) {
        super(cause);
    }
}
