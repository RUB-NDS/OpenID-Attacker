package wsattacker.sso.openid.attacker.gui.server;

import java.awt.Color;
import java.awt.Component;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import wsattacker.sso.openid.attacker.log.RequestType;
import static wsattacker.sso.openid.attacker.log.RequestType.XRDS;

public class TypeRenderer extends DefaultTableCellRenderer {

    public Color getColor(RequestType type) {
        Color result;
        switch (type) {
            case ASSOCIATION:
                result = Color.YELLOW;
                break;
            case XRDS:
                result = Color.LIGHT_GRAY;
                break;
            case HTML:
                result = Color.BLUE;
                break;
            case TOKEN_VALID:
                result = Color.green;
                break;
            case TOKEN_ATTACK:
                result = Color.red;
                break;
            case CHECK_AUTHENTICATION:
                result = Color.CYAN;
                break;
            case ERROR:
                result = Color.MAGENTA;
                break;
            default:
                throw new AssertionError();
        }
        return result;
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        Component cell = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        if (value instanceof RequestType) {
            cell.setBackground(getColor((RequestType) value));
        }
        return cell;
    }
}
