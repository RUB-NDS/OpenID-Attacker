package wsattacker.sso.openid.attacker.gui.attack;

import javax.swing.JPanel;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameter;

public abstract class AbstractAttackParameterGui extends JPanel {

    public AbstractAttackParameterGui() {
    }

    public abstract String getParameterName();

    public abstract void doUnbind();

    public abstract AttackParameter getParameter();
}
