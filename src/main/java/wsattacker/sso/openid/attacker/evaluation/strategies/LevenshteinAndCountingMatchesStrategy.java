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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;

import java.util.concurrent.Future;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import wsattacker.sso.openid.attacker.evaluation.ExecutorServices;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider.User;

public class LevenshteinAndCountingMatchesStrategy implements DetermineUserStrategy {
    
    private final ExecutorService executor = ExecutorServices.getMultiThreadExecutor();
    
    /* Extracts the first 50 000 characters of the source body. */
    private String extractBody(String pageSource) {
        /*Document doc = Jsoup.parse(pageSource);
        Element body = doc.select("body").first();
        
        String bodyString = body.html();*/
        
        /*if (bodyString.length() > 50000)
            bodyString = bodyString.substring(0, 50000-1);*/
        
        if (pageSource.length() > 50000)
            pageSource = pageSource.substring(0, 50000-1);
        
        return pageSource;
    }

    @Override
    public ServiceProvider.User determineAuthenticatedUser(String pageSource, String url, ServiceProvider serviceProvider) {
        
        /* First: Compare URLs */
        List<String> victimSuccessUrls = serviceProvider.getVictimSuccessUrls();
        List<String> attackerSuccessUrls = serviceProvider.getAttackerSuccessUrls();
        List<String> failureUrls = serviceProvider.getFailureUrls();
        
        boolean successUrlEqual = true;
        boolean failureUrlNotEqual = true;
        for (String victimSuccessUrl: victimSuccessUrls) {
            for (String attackerSuccessUrl: attackerSuccessUrls) {
                if (!victimSuccessUrl.equalsIgnoreCase(attackerSuccessUrl)) {
                    successUrlEqual = false;
                    break;
                }
            }
            
            for (String failureUrl: failureUrls) {
                if (victimSuccessUrl.equalsIgnoreCase(failureUrl)) {
                    failureUrlNotEqual = false;
                    break;
                }
            }
        }
        
        if (successUrlEqual && failureUrlNotEqual) {
            System.out.println("Determinte authenticated user by URL...");
            
            if (!url.equalsIgnoreCase(victimSuccessUrls.get(0))) {
                return User.ERROR;
            }
        }
        
        
        String pageBody = extractBody(pageSource);
        
        List<Callable<Float>> callables = new ArrayList<>();

        for (String attackerSuccessPageSource : serviceProvider.getAttackerSuccessPageSources()) {
            callables.add(new StringSimilarityCallable(pageBody, extractBody(attackerSuccessPageSource)));
        }

        List<Future<Float>> attackerSuccessResults = null;
        try {
            attackerSuccessResults = executor.invokeAll(callables);
        } catch (InterruptedException ex) {
            Logger.getLogger(ServiceProvider.class.getName()).log(Level.SEVERE, null, ex);
        }

        callables.clear();        
        for (String victimSuccessPageSource : serviceProvider.getVictimSuccessPageSources()) {
            callables.add(new StringSimilarityCallable(pageBody, extractBody(victimSuccessPageSource)));
        }

        List<Future<Float>> victimSuccessResults = null;
        try {
            victimSuccessResults = executor.invokeAll(callables);
        } catch (InterruptedException ex) {
            Logger.getLogger(ServiceProvider.class.getName()).log(Level.SEVERE, null, ex);
        }

        callables.clear();
        for (String failurePageSource :serviceProvider.getFailurePageSources()) {
            callables.add(new StringSimilarityCallable(pageBody, extractBody(failurePageSource)));
        }

        List<Future<Float>> failureResults = null;
        try {
            failureResults = executor.invokeAll(callables);
        } catch (InterruptedException ex) {
            Logger.getLogger(ServiceProvider.class.getName()).log(Level.SEVERE, null, ex);
        }

        float success = 0.0f;
        float failure = 0.0f;
        float victimSuccess = 0.0f;
        float attackerSuccess = 0.0f;

        for (Future<Float> result : attackerSuccessResults) {
            try {
                float currentAttackerSuccess = result.get();
                System.out.println("currentAttackerSuccess: " + currentAttackerSuccess);
                attackerSuccess += currentAttackerSuccess;
            } catch (InterruptedException ex) {
                Logger.getLogger(ServiceProvider.class.getName()).log(Level.SEVERE, null, ex);
            } catch (ExecutionException ex) {
                Logger.getLogger(ServiceProvider.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        for (Future<Float> result : victimSuccessResults) {
            try {
                float currentVictimSuccess = result.get();
                System.out.println("currentVictimSuccess: " + currentVictimSuccess);
                victimSuccess += currentVictimSuccess;
            } catch (InterruptedException ex) {
                Logger.getLogger(ServiceProvider.class.getName()).log(Level.SEVERE, null, ex);
            } catch (ExecutionException ex) {
                Logger.getLogger(ServiceProvider.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        for (Future<Float> result : failureResults) {
            try {
                float currentFailure = result.get();
                System.out.println("currentFailure: " + currentFailure);
                
                failure += currentFailure;
            } catch (InterruptedException ex) {
                Logger.getLogger(ServiceProvider.class.getName()).log(Level.SEVERE, null, ex);
            } catch (ExecutionException ex) {
                Logger.getLogger(ServiceProvider.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        success = victimSuccess < attackerSuccess ? (victimSuccess/victimSuccessResults.size()) : (attackerSuccess/attackerSuccessResults.size());
        failure /= failureResults.size();
     
        if (success < failure) {
            String victimUsername = serviceProvider.getVictimUsername();
            String attackerUsername = serviceProvider.getAttackerUsername();
            
            int victimMatches = StringUtils.countMatches(pageSource, StringUtils.capitalize(victimUsername));
            victimMatches += StringUtils.countMatches(pageSource, victimUsername.toLowerCase());
            int attackerMatches = StringUtils.countMatches(pageSource, StringUtils.capitalize(attackerUsername));
            attackerMatches += StringUtils.countMatches(pageSource, attackerUsername.toLowerCase());
            
            System.out.println("victimMatches: " + victimMatches + ", attackerMatches: " + attackerMatches);
            
            if (victimMatches > attackerMatches) {                
                System.out.println("authenticated user: VICTIM");
                return ServiceProvider.User.VICTIM;
            } else if (attackerMatches > victimMatches) {
                System.out.println("authenticated user: ATTACKER");
                return ServiceProvider.User.ATTACKER;
            } else {
                System.out.println("authenticated user: NONE");
                return ServiceProvider.User.NONE;
            }
        } else {
            System.out.println("success: " + success + ", failure: " + failure);
            System.out.println("authenticated user: ERROR");
            return ServiceProvider.User.ERROR;
        }
    }
}