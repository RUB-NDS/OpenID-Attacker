/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sso.openid.attacker.evaluation.training;

import java.io.Serializable;
import wsattacker.sso.openid.attacker.evaluation.LoginResult;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider.User;

/**
 *
 * @author christiankossmann
 */
public class TrainingResult implements Serializable {
    private final User type;
    private final LoginResult loginResult;
    
    public TrainingResult(User type, LoginResult loginResult) {
        this.type = type;
        this.loginResult = loginResult;
    }

    public User getType() {
        return type;
    }

    public LoginResult getLoginResult() {
        return loginResult;
    }
}