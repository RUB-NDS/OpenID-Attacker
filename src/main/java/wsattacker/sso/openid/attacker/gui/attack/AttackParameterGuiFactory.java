package wsattacker.sso.openid.attacker.gui.attack;

import wsattacker.sso.openid.attacker.attack.parameter.AttackParameter;
import wsattacker.sso.openid.attacker.attack.parameter.SearchReplaceAttackParameter;

public class AttackParameterGuiFactory {

    public static AbstractAttackParameterGui createGui(AttackParameter parameter) {
        AbstractAttackParameterGui gui;
//        if (parameter instanceof SearchReplaceAttackParameter) {
        gui = new SearchReplaceAttackParameterGui((SearchReplaceAttackParameter) parameter);
//        } else {
//            gui = new AttackParameterGui(parameter);
//        }
        return gui;
    }
}
