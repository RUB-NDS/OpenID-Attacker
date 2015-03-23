package wsattacker.sso.openid.attacker.log.utilities;

import java.util.Map;

final public class PrintHelper {

    private PrintHelper() {
    }

    public static String mapToString(Map<String, String> theMap) {
        StringBuilder sb = new StringBuilder("");
        for (Map.Entry<String, String> entry : theMap.entrySet()) {
            sb.append(entry.getKey());
            sb.append(':');
            sb.append(entry.getValue());
            sb.append('\n');
        }
        return sb.toString();
    }
}
