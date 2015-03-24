/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sso.openid.attacker.evaluation.strategies;

import java.util.List;
import org.apache.commons.lang3.StringUtils;
import uk.ac.shef.wit.simmetrics.similaritymetrics.AbstractStringMetric;
import uk.ac.shef.wit.simmetrics.similaritymetrics.ChapmanLengthDeviation;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider.User;

/**
 *
 * @author christian
 */
public class LengthDeviationAndCountingMatchesStrategy implements DetermineUserStrategy {

    @Override
    public ServiceProvider.User determineAuthenticatedUser(String pageSource, ServiceProvider serviceProvider) {
        
        float success = 0.0f;
        float failure = 0.0f;
        
        AbstractStringMetric metric = new ChapmanLengthDeviation();
        
        for (String attackerSuccessPageSource: serviceProvider.getAttackerSuccessPageSources()) {
            float currentSuccess = metric.getSimilarity(pageSource, attackerSuccessPageSource);
            //System.out.println("success: " + currentSuccess);
            
            success += currentSuccess;
        }
        
        for (String failurePageSource: serviceProvider.getFailurePageSources()) {
            float currentFailure = metric.getSimilarity(pageSource, failurePageSource);
            //System.out.println("failure: " + currentFailure);
            
            failure += currentFailure;
        }
        
        if (success > failure) {
            String victimUsername = serviceProvider.getVictimUsername();
            String attackerUsername = serviceProvider.getAttackerUsername();
            
            int victimMatches = StringUtils.countMatches(pageSource, StringUtils.capitalize(victimUsername));
            victimMatches += StringUtils.countMatches(pageSource, victimUsername.toLowerCase());
            int attackerMatches = StringUtils.countMatches(pageSource, StringUtils.capitalize(attackerUsername));
            attackerMatches += StringUtils.countMatches(pageSource, attackerUsername.toLowerCase());
            
            //System.out.println("victimMatches: " + victimMatches + ", attackerMatches: " + attackerMatches);
            
            if (victimMatches > attackerMatches) {                
                return ServiceProvider.User.VICTIM;
            } else if (attackerMatches > victimMatches) {
                return ServiceProvider.User.ATTACKER;
            } else {
                return ServiceProvider.User.NONE;
            }
        } else {
            return User.ERROR;
        }
    }
    
}
