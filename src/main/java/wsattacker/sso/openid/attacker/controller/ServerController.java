package wsattacker.sso.openid.attacker.controller;

import java.util.List;
import wsattacker.sso.openid.attacker.config.OpenIdServerConfiguration;
import wsattacker.sso.openid.attacker.log.RequestLogEntry;
import wsattacker.sso.openid.attacker.log.RequestLogger;
import wsattacker.sso.openid.attacker.server.OpenIdServer;

public class ServerController {

    // singleton:
    private static OpenIdServer server = new OpenIdServer();
    private static OpenIdServerConfiguration config = OpenIdServerConfiguration.getInstance();

    public OpenIdServer getServer() {
        return server;
    }

    public OpenIdServerConfiguration getConfig() {
        return config;
    }

    public List<RequestLogEntry> getRequestLog() {
        return RequestLogger.getInstance().getEntryList();
    }
}
