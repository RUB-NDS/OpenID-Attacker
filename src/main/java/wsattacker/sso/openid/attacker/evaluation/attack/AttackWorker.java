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

import java.util.List;
import javax.swing.SwingWorker;
import org.apache.commons.lang3.time.StopWatch;
import wsattacker.sso.openid.attacker.evaluation.EvaluationResult;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider;

public class AttackWorker extends SwingWorker<Void, AttackResult> {

    private AbstractAttack attack;
    //private final HtmlOutput htmlOutput;
    private final String attackName;
    
    private List<AttackResult> attackResults;
    private final EvaluationResult evaluationResult;
    
    public AttackWorker(final String attackName, final ServiceProvider serviceProvider,
            EvaluationResult evaluationResult) {
        this.attackName = attackName;
        this.evaluationResult = evaluationResult;
        
        switch (attackName) {
            case "Signature Exclusion":
                attack = new SignatureExclusionAttack(serviceProvider);
                break;
            case "Replay":
                attack = new ReplayAttack(serviceProvider);
                break;
            case "Token Recipient Confusion":
                attack = new TokenRecipientConfusionAttack(serviceProvider);
                break;
            case "ID Spoofing":
                attack = new IdSpoofingAttack(serviceProvider);
                break;
            case "Key Confusion":
                attack = new KeyConfusionAttack(serviceProvider);
                break;
            case "Discovery Spoofing":
                attack = new DiscoverySpoofingAttack(serviceProvider);
                break;
            case "Parameter Forgery":
                attack = new ParameterForgeryAttack(serviceProvider);
                break;
            case "XXE/DTD":
                attack = new DtdAttack(serviceProvider);
                break;
            case "Malicious Metadata":
                attack = new MaliciousMetadataAttack(serviceProvider);
                break;
            case "Same IdP Delegation":
                attack = new SameIdpDelegationAttack(serviceProvider);
                break;
        }
    }
    
    
    
    @Override
    protected Void doInBackground() throws Exception {
        
        System.out.println("##### Start " + attackName + " Attack #####");
        
        StopWatch stopWatch = new StopWatch();
        stopWatch.start();
        
        this.attackResults = attack.performAttacks();

        stopWatch.stop();
        evaluationResult.addInvestigationTime(stopWatch.getTime()/1000);
        
        return null;
    }

    @Override
    protected void done() {
        evaluationResult.addAttackResults(attackName, attackResults);
    }
}