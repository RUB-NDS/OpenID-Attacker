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

import org.apache.commons.lang3.StringUtils;
import uk.ac.shef.wit.simmetrics.similaritymetrics.AbstractStringMetric;
import uk.ac.shef.wit.simmetrics.similaritymetrics.ChapmanLengthDeviation;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider.User;

public class LengthDeviationAndCountingMatchesStrategy implements DetermineUserStrategy {

    @Override
    public ServiceProvider.User determineAuthenticatedUser(String pageSource, String url, ServiceProvider serviceProvider) {
        
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
