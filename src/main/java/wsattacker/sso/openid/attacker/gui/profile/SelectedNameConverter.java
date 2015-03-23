package wsattacker.sso.openid.attacker.gui.profile;

import org.jdesktop.beansbinding.Converter;
import wsattacker.sso.openid.attacker.attack.profile.AttackProfile;

public class SelectedNameConverter extends Converter<AttackProfile, String> {

    @Override
    public String convertForward(AttackProfile value) {
        return value.getName();
    }

    @Override
    public AttackProfile convertReverse(String value) {
        throw new UnsupportedOperationException("Read only conversation");
    }
}
