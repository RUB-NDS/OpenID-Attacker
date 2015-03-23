package wsattacker.sso.openid.attacker.server.status;

public enum Status {

    STOPPED("Stopped"), RUNNING("Running");
    final private String readableName;

    private Status(String readableName) {
        this.readableName = readableName;
    }

    @Override
    public String toString() {
        return readableName;
    }
}
