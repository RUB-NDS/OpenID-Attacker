/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sso.openid.attacker.gui;

import java.net.URL;
import javax.swing.ImageIcon;
import org.jdesktop.beansbinding.Converter;
import wsattacker.sso.openid.attacker.server.status.Status;

/**
 *
 * @author christian
 */
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