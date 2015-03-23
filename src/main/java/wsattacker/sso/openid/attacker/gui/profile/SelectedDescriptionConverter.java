package wsattacker.sso.openid.attacker.gui.profile;

import org.jdesktop.beansbinding.Converter;
import wsattacker.sso.openid.attacker.attack.profile.AttackProfile;

public class SelectedDescriptionConverter extends Converter<AttackProfile, String> {

    @Override
    public String convertForward(AttackProfile value) {
        return value.getDescription();
    }

    @Override
    public AttackProfile convertReverse(String value) {
        throw new UnsupportedOperationException("Read only conversation");
    }
}
