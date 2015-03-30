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



import wsattacker.sso.openid.attacker.evaluation.strategies.DetermineUserStrategy;
import wsattacker.sso.openid.attacker.evaluation.strategies.LevenshteinAndCountingMatchesStrategy;
import java.io.Serializable;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import wsattacker.sso.openid.attacker.config.OpenIdServerConfiguration;
import wsattacker.sso.openid.attacker.evaluation.strategies.InjectJavaScriptLoginStrategy;
import wsattacker.sso.openid.attacker.evaluation.strategies.LoginStrategy;

public class ServiceProvider implements Serializable {
    private final String url;
    
    private final Map<String, String> victimData;
    private final Map<String, String> attackerData;
    
    private final List<String> victimSuccessPageSources = new ArrayList<>();
    private final List<String> attackerSuccessPageSources = new ArrayList<>();
    private final List<String> failurePageSources = new ArrayList<>();
    
    private final List<String> victimSuccessUrls = new ArrayList<>();
    private final List<String> attackerSuccessUrls = new ArrayList<>();
    private final List<String> failureUrls = new ArrayList<>();
    
    private transient DetermineUserStrategy determineUserStrategy;
    private transient LoginStrategy loginStrategy;
    
    /* Indicates which user should be or is logged in. */
    public enum User {
        VICTIM("Victim"), ATTACKER("Attacker"), ERROR("Error"), NONE("None"), ATTACKER_RANDOM("Attacker Random");
        private final String representation;

        private User(String representation) {
            this.representation = representation;
        }

        @Override
        public String toString() {
            return representation;
        }
    }
    
    public ServiceProvider(String url) {
        this.url = url;
        
        this.victimData = OpenIdServerConfiguration.getAnalyzerInstance().getValidUser().getUserDataMap();
        this.attackerData = OpenIdServerConfiguration.getAttackerInstance().getValidUser().getUserDataMap();
    }
    
    /* Logs the user in to Service Provider and returns the source code. */
    public LoginResult login(User user) {
        return getLoginStrategy().login(user, this);
    }
    
    /**
     * This is a wrapper method of the method login, which
 handles the actual loginAndDetermineAuthenticatedUser procedure. Apart from the loginAndDetermineAuthenticatedUser this method
 deletes all cookies, takes a screenshot and determines the authenticated
 user.
     * 
     * @param openId The user that should be logged in (victim or attacker).
     * @return Screenshot and authenticated user.
     */
    public LoginResult loginAndDetermineAuthenticatedUser(User openId) {        
        
        LoginResult loginResult = login(openId);
        
        User user = determineAuthenticatedUser(loginResult.getPageSource(), loginResult.getUrlAfterLogin());
        loginResult.setAuthenticatedUser(user);
        
        return loginResult;
    }
    
    /**
     * Determines the authenticated user based on the training sets.
     * 
     * @param pageSource The page source of the loginAndDetermineAuthenticatedUser attempt.
     * @return The authenticated user.
     */
    public User determineAuthenticatedUser(String pageSource, String url) {
        
        
        return getDetermineUserStrategy().determineAuthenticatedUser(pageSource, url, this);
    }
        
    public void addVictimSuccessPageSource(String pageSource) {
        victimSuccessPageSources.add(pageSource);
    }
    
    public void addAttackerSuccessPageSource(String pageSource) {
        attackerSuccessPageSources.add(pageSource);
    }
    
    public void addFailurePageSource(String pageSource) {
        failurePageSources.add(pageSource);
    }
    
    public String getUrl() {
        return url;
    }

    public String getVictimOpenId() {
        return victimData.get("claimed_id");
    }

    public String getVictimUsername() {
        return victimData.get("nickname");
    }

    public String getAttackerOpenId() {
        return attackerData.get("claimed_id");
    }

    public String getAttackerUsername() {
        return attackerData.get("nickname");
    }

    public Map<String, String> getVictimData() {
        return victimData;
    }

    public Map<String, String> getAttackerData() {
        return attackerData;
    }    

    public List<String> getVictimSuccessPageSources() {
        return victimSuccessPageSources;
    }

    public List<String> getAttackerSuccessPageSources() {
        return attackerSuccessPageSources;
    }

    public List<String> getFailurePageSources() {
        return failurePageSources;
    }

    private DetermineUserStrategy getDetermineUserStrategy() {
        if (determineUserStrategy == null) {
            determineUserStrategy = new LevenshteinAndCountingMatchesStrategy();
        }
        
        return determineUserStrategy;
    }

    private LoginStrategy getLoginStrategy() {
        if (loginStrategy == null) {
            loginStrategy = new InjectJavaScriptLoginStrategy();
        }
        
        return loginStrategy;
    }
    
    public void addVictimSuccessUrl(String url) {
        this.victimSuccessUrls.add(url);
    }
    
    public void addAttackerSuccessUrl(String url) {
        this.attackerSuccessUrls.add(url);
    }
    
    public void addFailureUrl(String url) {
        this.failureUrls.add(url);
    }

    public List<String> getVictimSuccessUrls() {
        return victimSuccessUrls;
    }

    public List<String> getAttackerSuccessUrls() {
        return attackerSuccessUrls;
    }

    public List<String> getFailureUrls() {
        return failureUrls;
    }
}