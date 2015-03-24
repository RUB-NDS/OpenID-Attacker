/*
 * OpenID Attacker
 * (C) 2015 Christian Mainka & Christian Koßmann
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
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
            case XXE:
                result = Color.PINK;
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
