package wsattacker.sso.openid.attacker.gui.log;

import org.jdesktop.beansbinding.Converter;
import wsattacker.sso.openid.attacker.log.RequestLogEntry;

public class SelectedResponseConverter extends Converter<RequestLogEntry, String> {

    @Override
    public String convertForward(RequestLogEntry value) {
        return value.getResponse();
    }

    @Override
    public RequestLogEntry convertReverse(String value) {
        throw new UnsupportedOperationException("Read only conversation");
    }
}
