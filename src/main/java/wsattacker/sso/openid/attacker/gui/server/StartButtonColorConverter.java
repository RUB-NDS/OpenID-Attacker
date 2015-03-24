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
