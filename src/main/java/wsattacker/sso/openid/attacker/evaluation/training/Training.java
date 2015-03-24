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
package wsattacker.sso.openid.attacker.evaluation.training;

import wsattacker.sso.openid.attacker.attack.parameter.AttackParameter;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameterKeeper;
import wsattacker.sso.openid.attacker.attack.parameter.utilities.HttpMethod;
import wsattacker.sso.openid.attacker.config.OpenIdServerConfiguration;
import wsattacker.sso.openid.attacker.controller.ServerController;
import wsattacker.sso.openid.attacker.evaluation.LoginResult;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider.User;

public class Training {
    private final ServerController controller = new ServerController();
    private final AttackParameterKeeper keeper = controller.getServer().getParameterConfiguration();
    
    public enum ErrorType {
        ERROR_1,
        ERROR_2,
        ERROR_3
    }    
    
    private final ServiceProvider serviceProvider;
    
    public Training(ServiceProvider serviceProvider) {
        this.serviceProvider = serviceProvider;        
    }
    
    public TrainingResult performSuccessfulLogin(User user) {
        keeper.resetAllParameters();
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(false);
        
        LoginResult loginResult = null;
        
        switch (user) {
            case ATTACKER:
                loginResult = serviceProvider.login(ServiceProvider.User.ATTACKER);
                break;
            case VICTIM:
                loginResult = serviceProvider.login(ServiceProvider.User.VICTIM); 
                break;
        }
            
        return new TrainingResult(user, loginResult);
    }   
    
    public TrainingResult performUnsuccessfulLogin(ErrorType error) {
        keeper.resetAllParameters();
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(true);
        
        AttackParameter claimedIDParameter = keeper.getParameter("openid.claimed_id");
        AttackParameter identityParameter = keeper.getParameter("openid.identity");
        AttackParameter returnToParameter = keeper.getParameter("openid.return_to");
        AttackParameter sigParameter = keeper.getParameter("openid.sig");
        
        switch (error) {
            case ERROR_1:
                // 1. remove claimed_id and identity
                claimedIDParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
                identityParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
                break;
            case ERROR_2:
                // 2. remove return_to
                returnToParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
                break;
            case ERROR_3:
                // 3. remove sig and claimed_id
                claimedIDParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
                sigParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
                break;
        }
        
        LoginResult loginResult = serviceProvider.login(User.ATTACKER);
        
        OpenIdServerConfiguration.getAttackerInstance().setPerformAttack(false);
        
        return new TrainingResult(User.ERROR, loginResult);
    }
}
