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
package wsattacker.sso.openid.attacker.evaluation;

import java.awt.GraphicsDevice;
import java.awt.GraphicsEnvironment;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
import org.openqa.selenium.By;
import org.openqa.selenium.Dimension;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.Point;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxProfile;
import wsattacker.sso.openid.attacker.gui.evaluation.EvaluationGui;

public class SeleniumBrowser {
    private static WebDriver INSTANCE;
    
    private SeleniumBrowser() {
    
    }   
    
    public static WebDriver getWebDriver() {
        
        if (INSTANCE == null || hasQuit(INSTANCE) || INSTANCE.getWindowHandles().isEmpty()) {
            // create chrome profile
            //ChromeOptions options = new ChromeOptions();
            //options.addExtensions(new File("adblock.crx"));
            
            FirefoxProfile profile = new FirefoxProfile();
            
            // install adblock plus
            File tmpFile = new File("adblock.xpi");
            try {
                InputStream inputStream = SeleniumBrowser.class.getResourceAsStream("/adblock_firefox.xpi");
                FileUtils.copyInputStreamToFile(inputStream, tmpFile);
                profile.addExtension(tmpFile);
            } catch (IOException ex) {
                Logger.getLogger(EvaluationGui.class.getName()).log(Level.SEVERE, null, ex);
            }

            // disable local and session storage
            // some websites (e.g. stackoverflow) use those storages in addition
            // to session cookies
            profile.setPreference("dom.storage.enabled", false);
            
            // start new Firefox instance
            INSTANCE = new FirefoxDriver(profile);
            
            // screen size
            GraphicsDevice gd = GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice();
            int width = gd.getDisplayMode().getWidth();
            int height = gd.getDisplayMode().getHeight();
            
            width = width > 1440 ? 1440 : width;
            height = height > 900 ? 900 : height;
            
            INSTANCE.manage().window().setPosition(new Point(0,0));
            INSTANCE.manage().window().setSize(new Dimension(width, height));
            
            tmpFile.delete();
        }
        
        return INSTANCE;
    }
    
    private static boolean hasQuit(WebDriver driver) {
        try {
            driver.getTitle();
            return false;
        } catch (Exception e) {
            return true;
        }
}
    
    public static void quitWebDriver() {
        getWebDriver().quit();
        
        INSTANCE = null;
    }
    
    public static void loginVictimToWordpress() {
        WebDriver driver = getWebDriver();
        
        JavascriptExecutor jse = (JavascriptExecutor)driver;
        jse.executeScript("var win = window.open('https://de.wordpress.com/wp-login.php');");
        
        List<String> windowhandles = new ArrayList<>(driver.getWindowHandles());
        driver.switchTo().window(windowhandles.get(1));
        
        WebElement element = driver.findElement(By.id("user_login"));
        element.clear();
        element.sendKeys("victim123456789");
        
        element = driver.findElement(By.id("user_pass"));
        element.clear();
        element.sendKeys("Victim1234!");
        
        element.submit();
        
        
        /*windowhandles.forEach((windowHandle) -> {
            System.out.println("windowHandle: " + windowHandle);
        });*/
        
        driver.switchTo().window(windowhandles.get(0));
    }
    
    public static File takeScreenshot() {
        // take a screenshot
        return ((TakesScreenshot)getWebDriver()).getScreenshotAs(OutputType.FILE);
        
        // construct file name
        /*imageNumber++;
        String filename = imageNumber + ".png";
        
        try {
            // copy file in pictures folder
            FileUtils.copyFile(file, new File(System.getProperty("user.home") + "/Documents/images/" + filename));
        } catch (IOException ex) {
            Logger.getLogger(ServiceProvider.class.getName()).log(Level.SEVERE, null, ex);
        }*/
    }
    
    public static void deleteAllCookies() {
        SeleniumBrowser.getWebDriver().manage().deleteAllCookies();
    }
}