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
package wsattacker.sso.openid.attacker.gui;

import java.net.URL;
import javax.swing.ImageIcon;
import org.jdesktop.beansbinding.Converter;
import wsattacker.sso.openid.attacker.server.status.Status;

public class ServerStatusToIconConverter extends Converter<Status, ImageIcon> {

    @Override
    public ImageIcon convertForward(Status s) {
        if (s == Status.RUNNING) {
            return createImageIcon("play.png", "play icon");
        }
        
        return createImageIcon("stop.png", "stop icon");
    }

    @Override
    public Status convertReverse(ImageIcon t) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    /** Returns an ImageIcon, or null if the path was invalid. */
    protected ImageIcon createImageIcon(String path, String description) {
        URL imgURL = getClass().getClassLoader().getResource(path);
        if (imgURL != null) {
            return new ImageIcon(imgURL, description);
        } else {
            System.err.println("Couldn't find file: " + path);
            return null;
        }
    }
}