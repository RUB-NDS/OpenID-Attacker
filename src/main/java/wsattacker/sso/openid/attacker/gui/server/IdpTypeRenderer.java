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
import wsattacker.sso.openid.attacker.server.IdpType;

/**
 *
 * @author christiankossmann
 */
public class IdpTypeRenderer extends DefaultTableCellRenderer {

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        Component cell = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        if (value instanceof IdpType) {
            IdpType idpType = (IdpType) value;
            
            switch (idpType) {
                case ATTACKER:
                    cell.setBackground(Color.RED);
                    break;
                case ANALYZER:
                    cell.setBackground(Color.GREEN);
                    break;
            }
        }
        return cell;
    } 
}
