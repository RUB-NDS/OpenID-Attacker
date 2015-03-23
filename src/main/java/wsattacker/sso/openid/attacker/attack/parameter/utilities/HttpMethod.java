package wsattacker.sso.openid.attacker.attack.parameter.utilities;

import java.io.Serializable;

public enum HttpMethod implements Serializable {

    GET("GET"), POST("POST"), DO_NOT_SEND("Don't send");
    private String representation;

    private HttpMethod(String representation) {
        this.representation = representation;
    }

    @Override
    public String toString() {
        return representation;
    }
}
