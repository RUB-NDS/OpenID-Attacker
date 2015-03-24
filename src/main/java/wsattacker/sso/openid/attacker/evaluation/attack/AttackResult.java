/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package wsattacker.sso.openid.attacker.evaluation.attack;

import java.io.Serializable;
import wsattacker.sso.openid.attacker.evaluation.LoginResult;

/**
 *
 * @author christiankossmann
 */
public class AttackResult implements Serializable {
    private final String description;
    private final LoginResult loginResult;
    private final Result result;
    private final Interpretation interpretation;
    
    public enum Result {
        SUCCESS, FAILURE, NOT_PERFORMABLE, NOT_DETECTABLE
    }
    
    public enum Interpretation {
        CRITICAL, RESTRICTED, PREVENTED, NEUTRAL
    }
    
    public AttackResult(String description, LoginResult loginResult, Result result, Interpretation interpretation) {
        this.description = description;
        this.loginResult = loginResult;
        this.result = result;
        this.interpretation = interpretation;
    }

    public String getDescription() {
        return description;
    }

    public LoginResult getLoginResult() {
        return loginResult;
    }

    public Result getResult() {
        return result;
    }

    public Interpretation getInterpretation() {
        return interpretation;
    }
}
