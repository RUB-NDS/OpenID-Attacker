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
