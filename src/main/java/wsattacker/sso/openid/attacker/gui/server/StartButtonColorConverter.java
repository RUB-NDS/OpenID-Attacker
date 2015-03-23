package wsattacker.sso.openid.attacker.gui.server;

import java.awt.Color;
import org.jdesktop.beansbinding.Converter;
import wsattacker.sso.openid.attacker.server.status.Status;

public class StartButtonColorConverter extends Converter<Status, Color> {

	final private Color COLOR_NORMAL = new Color(238, 238, 238);
	final private Color COLOR_NOT_RUNNING = Color.RED;

    public StartButtonColorConverter() {
    }

    @Override
    public Color convertForward(Status value) {
        Color result = COLOR_NOT_RUNNING;
        if (Status.RUNNING.equals(value)) {
            result = COLOR_NORMAL;
        }
        return result;
    }

    @Override
    public Status convertReverse(Color value) {
        throw new UnsupportedOperationException("Read only."); //To change body of generated methods, choose Tools | Templates.
    }
}
