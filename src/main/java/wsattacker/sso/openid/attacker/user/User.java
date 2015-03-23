package wsattacker.sso.openid.attacker.user;

import java.util.LinkedHashMap;
import java.util.Map;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

@XmlRootElement(name = "User")
public class User extends UserDataCollector {

    public static final String NAME_IDENTIFIER = "identity";
    public static final String NAME_CLAIMED_ID = "claimed_id";

    public User() {
        super();
        setIdentifier(NAME_IDENTIFIER);
        setClaimedId(NAME_CLAIMED_ID);
    }

    @XmlTransient
    public String getIdentifier() {
        return getByName(NAME_IDENTIFIER).getValue();
    }

    public void setIdentifier(String identifier) {
        set(NAME_IDENTIFIER, identifier);
    }

    @XmlTransient
    public String getClaimedId() {
        return getByName(NAME_CLAIMED_ID).getValue();
    }

    public void setClaimedId(String claimedId) {
        set(NAME_CLAIMED_ID, claimedId);
    }

    public Map getUserDataMap() {
        Map<String, String> result = new LinkedHashMap<>();
        for (UserData data : getDataList()) {
            String name = data.getName();
            if (!result.containsKey(name)) {
                String value = data.getValue();
                result.put(name, value);
            }
        }
        return result;
    }
}
