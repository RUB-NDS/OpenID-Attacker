/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sso.openid.attacker.evaluation;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider.User;
import wsattacker.sso.openid.attacker.log.RequestLogEntry;
import wsattacker.sso.openid.attacker.log.RequestType;

/**
 *
 * @author christiankossmann
 */
public class LoginResult implements Serializable {
    private User authenticatedUser = null;
    private final String pageSource;
    private List<RequestLogEntry> logEntries;
    private File screenshot;
    
    public LoginResult(String pageSource, List<RequestLogEntry> logEntries,
            File screenshot) {
        
            this.pageSource = pageSource;
            this.logEntries = logEntries;
        try {   
            String filename = new SimpleDateFormat("yyyy-MM-dd_hh-mm-ss'.png'").format(new Date());
            File newFile = new File("images/" + filename);
            FileUtils.copyFile(screenshot, newFile);
            this.screenshot = newFile;
        } catch (IOException ex) {
            Logger.getLogger(LoginResult.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void setScreenshot(File screenshot) {
        try {
            FileUtils.copyFile(screenshot, this.screenshot);
        } catch (IOException ex) {
            Logger.getLogger(LoginResult.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public ServiceProvider.User getAuthenticatedUser() {
        return authenticatedUser;
    }

    public void setAuthenticatedUser(User authenticatedUser) {
        this.authenticatedUser = authenticatedUser;
    }

    public String getPageSource() {
        return pageSource;
    }

    public List<RequestLogEntry> getLogEntries() {
        return logEntries;
    }
    
    public void addLogEntriesAtStart(List<RequestLogEntry> logEntries) {
        this.logEntries.addAll(0, logEntries);
    }
    
    public void addLogEntriesAtEnd(List<RequestLogEntry> logEntries) {
        this.logEntries.addAll(logEntries);
    }

    public void setLogEntries(List<RequestLogEntry> logEntries) {
        this.logEntries = logEntries;
    }
    
    public RequestLogEntry getLogEntryOfToken() {
        RequestLogEntry logEntryOfToken = null;
        
        for (RequestLogEntry logEntry: logEntries) {
            if (logEntry.getType() == RequestType.TOKEN_ATTACK || logEntry.getType() == RequestType.TOKEN_VALID) {
                logEntryOfToken = logEntry;
                break;
            }
        }
        
        return logEntryOfToken;
    }
    
    public boolean hasDirectVerification() {
        for (RequestLogEntry logEntry: logEntries) {
            if (logEntry.getType() == RequestType.CHECK_AUTHENTICATION) {
                return true;
            }
        }
        
        return false;
    }
    
    public boolean hasAssociation() {
        for (RequestLogEntry logEntry: logEntries) {
            if (logEntry.getType() == RequestType.ASSOCIATION) {
                return true;
            }
        }
        
        return false;
    }
    
    public boolean hasXxe() {
        for (RequestLogEntry logEntry: logEntries) {
            if (logEntry.getType() == RequestType.XXE) {
                return true;
            }
        }
        
        return false;
    }
    
    public boolean hasHtmlDiscovery() {
        for (RequestLogEntry logEntry: logEntries) {
            if (logEntry.getType() == RequestType.HTML) {
                return true;
            } else if (logEntry.getType() == RequestType.TOKEN_VALID ||
                    logEntry.getType() == RequestType.TOKEN_ATTACK) {
                break;
            }
        }
        return false;
    }
    
    public boolean hasXrdsDiscovery() {
        for (RequestLogEntry logEntry: logEntries) {
            if (logEntry.getType() == RequestType.XRDS) {
                return true;
            } else if (logEntry.getType() == RequestType.TOKEN_VALID ||
                    logEntry.getType() == RequestType.TOKEN_ATTACK) {
                break;
            }
        }
        return false;
    }

    public File getScreenshot() {
        return screenshot;
    }
}
