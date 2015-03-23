package wsattacker.sso.openid.attacker.log;

public enum RequestType {

    ASSOCIATION("Association"), XRDS("XRDS"), HTML("HTML"), TOKEN_VALID("Token Valid"), TOKEN_ATTACK("Token Attack"), ERROR("Error"), CHECK_AUTHENTICATION("Check Authentication");
	private String representation;

    private RequestType(String representation) {
        this.representation = representation;
    }

    @Override
    public String toString() {
        return representation;
    }
}
