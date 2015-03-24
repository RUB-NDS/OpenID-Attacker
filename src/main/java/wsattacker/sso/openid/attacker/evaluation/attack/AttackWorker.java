/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sso.openid.attacker.evaluation.attack;

import java.util.List;
import javax.swing.SwingWorker;
import org.apache.commons.lang3.time.StopWatch;
import wsattacker.sso.openid.attacker.evaluation.EvaluationResult;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider;

/**
 *
 * @author christiankossmann
 */
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
                attack = new XxeAttack(serviceProvider);
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