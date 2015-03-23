package wsattacker.sso.openid.attacker.discovery.xrds;

public enum OpenIdVersion {

    VERSION_10("OpenID v1.0", "http://openid.net/signon/1.0", "http://openid.net/signon/1.0"),
    VERSION_11("OpenID v1.1", "http://openid.net/signon/1.1", "http://openid.net/signon/1.1"),
    VERSION_20_OP_IDENTIFIER_ELEMENT("OpenID v2.0 - OP Identifier Element", "http://specs.openid.net/auth/2.0/server", "http://specs.openid.net/auth/2.0"),
    VERSION_20_CLAIMED_IDENTIFIER_ELEMENT("OpenID v2.0 - Claimed Identifier Element", "http://specs.openid.net/auth/2.0/signon", "http://specs.openid.net/auth/2.0");
    private final String representation, URI, NS;

    private OpenIdVersion(String representation, String URI, String NS) {
        this.representation = representation;
        this.URI = URI;
        this.NS = NS;
    }

    public String getURI() {
        return this.URI;
    }

    public String getNS() {
        return this.NS;
    }

    @Override
    public String toString() {
        return representation;
    }
}
