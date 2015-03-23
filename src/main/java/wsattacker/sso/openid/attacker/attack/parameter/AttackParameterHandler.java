package wsattacker.sso.openid.attacker.attack.parameter;

import java.util.LinkedHashMap;
import java.util.Map;
import wsattacker.sso.openid.attacker.attack.parameter.utilities.HttpMethod;
import wsattacker.sso.openid.attacker.config.OpenIdServerConfiguration;

final public class AttackParameterHandler {

    private AttackParameterHandler() {
    }

    public static void updateValidParameters(AttackParameterKeeper keeper, final Map<String, String> validParameterMap) {
        for (Map.Entry<String, String> entry : validParameterMap.entrySet()) {
            String name = entry.getKey();
            String value = entry.getValue();
            keeper.addOrUpdateParameterValidValue(name, value);
        }
    }

    public static void updateAttackParameters(AttackParameterKeeper keeper, final Map<String, String> attackParameterMap) {
        for (Map.Entry<String, String> entry : attackParameterMap.entrySet()) {
            String name = entry.getKey();
            String value = entry.getValue();
            AttackParameter p = keeper.getParameter(name);
            if (p != null) {
//                if (name.equals("openid.sig")) {
                p.setAutomaticValue(value);
//                } else {
//                    p.setAttackValue(value);
//                }
            }
        }
    }

    public static Map<String, String> createToSignMap(final AttackParameterKeeper keeper) {
        Map<String, String> result = new LinkedHashMap<>();
        for (AttackParameter parameter : keeper) {
            String name = parameter.getName();
            String value;
            if (parameter.isAttackValueUsedForSignatureComputation()) {
                value = parameter.getAttackValue();
            } else {
                value = parameter.getValidValue();
            }
            result.put(name, value);
        }
        return result;
    }

    public static Map<String, String> createMapByMethod(final AttackParameterKeeper keeper, final HttpMethod method) {
        return createMapByMethod(keeper, method, OpenIdServerConfiguration.getInstance().isPerformAttack());
    }

    public static Map<String, String> createMapByMethod(final AttackParameterKeeper keeper, final HttpMethod method, final boolean attackPerformed) {
        Map<String, String> result = new LinkedHashMap<>();
        for (AttackParameter parameter : keeper) {
            // TODO: This is not very nice :)
            if (!attackPerformed && method.equals(HttpMethod.GET)) {
                result.put(parameter.getName(), parameter.getValidValue());
            } else {
                if (attackPerformed && method.equals(parameter.getValidMethod())) {
                    result.put(parameter.getName(), parameter.getValidValue());
                }
                if (attackPerformed && method.equals(parameter.getAttackMethod())) {
                    result.put(parameter.getName(), parameter.getAttackValue());
                }
            }
        }
        return result;
    }

    public static void addCustomParameter(AttackParameterKeeper keeper, String newName) {
        if (keeper.hasParameter(newName)) {
            throw new IllegalArgumentException(String.format("Parameter '%s' already exist", newName));
        }
        String validValue = String.format("Custom Parameter '%s'", newName);
        AttackParameter newParameter = keeper.addOrUpdateParameterValidValue(newName, validValue);
        newParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        newParameter.setAttackMethod(HttpMethod.GET);
        newParameter.setAttackValueUsedForSignatureComputation(true);
        newParameter.setAttackValue(validValue);
    }

    public static void removeParameter(AttackParameterKeeper keeper, String newName) {
        if (!keeper.hasParameter(newName)) {
            throw new IllegalArgumentException(String.format("Parameter '%s' does not exist", newName));
        }
        keeper.removeParameter(newName);
    }
}
