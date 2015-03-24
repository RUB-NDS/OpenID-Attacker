/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
