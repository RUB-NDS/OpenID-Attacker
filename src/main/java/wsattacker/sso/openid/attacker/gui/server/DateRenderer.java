package wsattacker.sso.openid.attacker.gui.server;

import java.text.DateFormat;
import javax.swing.table.DefaultTableCellRenderer;

public class DateRenderer extends DefaultTableCellRenderer {

	private final DateFormat formatter = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM);

    @Override
    public void setValue(Object value) {
        setText((value == null) ? "" : formatter.format(value));
    }
}
