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
package wsattacker.sso.openid.attacker.evaluation.strategies;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.NoAlertPresentException;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import wsattacker.sso.openid.attacker.config.OpenIdServerConfiguration;
import wsattacker.sso.openid.attacker.evaluation.LoginResult;
import wsattacker.sso.openid.attacker.evaluation.SeleniumBrowser;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider.User;
import wsattacker.sso.openid.attacker.log.RequestLogEntry;
import wsattacker.sso.openid.attacker.log.RequestLogger;

public class InjectJavaScriptLoginStrategy implements LoginStrategy {

    @Override
    public LoginResult login(User user, ServiceProvider serviceProvider) {
        // before loginAndDetermineAuthenticatedUser remove all cookies
        SeleniumBrowser.deleteAllCookies();
        
        // copy log entries before login
        List<RequestLogEntry> logEntriesBeforeLogin = new ArrayList<>(RequestLogger.getInstance().getEntryList());
        
        // open url
        WebDriver driver = SeleniumBrowser.getWebDriver();
        driver.get(serviceProvider.getUrl());
        
        /* Search the page for the OpenID input field. According to the
           standard it should be called "openid_identifier" but some other
           frequent names are also tried. */
        WebElement element = null;
        String[] possibleNames = {"openid_identifier", "openid", "openID",
            "openid_url", "openid:url", "user", "openid-url", "openid-identifier", "oid_identifier",
            "ctl00$Column1Area$OpenIDControl1$openid_url",
            "user_input"
        };
        
        for (String possibleName: possibleNames) {
            try {
                element = driver.findElement(By.name(possibleName));
                System.out.println("Find OpenID field with name: " + possibleName);
                //break;            
            } catch (NoSuchElementException exception) {
                //System.out.println("Cannot find: " + possibleName);
            }
        }
        
        // save old XRDS lcoation
        String oldIdentity = OpenIdServerConfiguration.getAttackerInstance().getHtmlConfiguration().getIdentity();
        
        /* If an input field is found, it is filled with the OpenID identifier.
           Selenium cannot set text of hidden input field, consequently,
           JavaScript is injected which performs this task. */
        if (element != null) {
            JavascriptExecutor jse = (JavascriptExecutor)driver;
            
            // set text of text field
            switch (user) {
                case VICTIM:
                    jse.executeScript("arguments[0].value='" + serviceProvider.getVictimOpenId() + "'", element);
                    break;
                case ATTACKER:
                    jse.executeScript("arguments[0].value='" + serviceProvider.getAttackerOpenId() + "'", element);
                    break;
                case ATTACKER_RANDOM:
                    String attackerOpenId = serviceProvider.getAttackerOpenId();
                    
                    if (attackerOpenId.endsWith("/")) {
                        attackerOpenId = attackerOpenId.substring(0, attackerOpenId.length()-1);
                    }
                    
                    String randomAttackerIdentity = attackerOpenId + RandomStringUtils.random(10, true, true);
                    OpenIdServerConfiguration.getAttackerInstance().getHtmlConfiguration().setIdentity(randomAttackerIdentity);
                    jse.executeScript("arguments[0].value='" + randomAttackerIdentity + "'", element);
                    break;
            }
            
            // special case: owncloud
            if (driver.getCurrentUrl().contains("owncloud")) {
                // set arbitrary password
                WebElement passwordElement = driver.findElement(By.id("password"));
                passwordElement.clear();
                passwordElement.sendKeys("xyz");
                
                WebElement submitElement = driver.findElement(By.id("submit"));
                
                jse.executeScript("var element = arguments[0]; element.removeAttribute('id');", submitElement);
            }
            
            // submit form
            jse.executeScript("var element = arguments[0];"
                            + "while(element.tagName != 'FORM') {"
                            +     "element = element.parentNode;"
                            +     "console.log(element);"
                            + "}"
                            + "element.submit();", element);
            
        }
        
        // click on accept in modal alert window (if present)
        try {
            driver.switchTo().alert().accept();
        } catch (NoAlertPresentException ex) {
            // do nothing
        }
        
        // wait 10 seconds: hopefully, all redirects are performed then
        try {            
            Thread.sleep(10000);
        } catch (InterruptedException ex) {
            Logger.getLogger(ServiceProvider.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        /* determines the log entries of the current login procedure:
           logEntries = logEntriesAfterLogin - logEntriesBeforeLogin
           (subtraction of sets) */
        List<RequestLogEntry> logEntriesAfterLogin = RequestLogger.getInstance().getEntryList();
        List<RequestLogEntry> logEntries = (List<RequestLogEntry>) CollectionUtils.subtract(logEntriesAfterLogin, logEntriesBeforeLogin);
        
        // invert order of log - should be chronological
        Collections.reverse(logEntries);
        
        File screenshot = SeleniumBrowser.takeScreenshot();
        String pageSource = driver.getPageSource();
        
        // restore old XRDS location
        OpenIdServerConfiguration.getAttackerInstance().getHtmlConfiguration().setIdentity(oldIdentity);
        
        return new LoginResult(pageSource, logEntries, screenshot);
    }
    
}
