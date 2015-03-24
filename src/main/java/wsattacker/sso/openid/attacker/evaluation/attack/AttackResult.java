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

import java.io.Serializable;
import wsattacker.sso.openid.attacker.evaluation.LoginResult;

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
