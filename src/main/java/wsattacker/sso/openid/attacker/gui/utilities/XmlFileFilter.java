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
package wsattacker.sso.openid.attacker.gui.utilities;

import java.io.File;
import javax.swing.filechooser.FileFilter;

public class XmlFileFilter extends FileFilter {

    private static final String DESCRIPTION = "XML-File";

    @Override
    public boolean accept(File file) {
        boolean result = false;
        if (file.isDirectory()) {
            result = true;
        } else if (file.getName().toLowerCase().endsWith(".xml")) {
            result = true;
        }
        return result;
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }
}
