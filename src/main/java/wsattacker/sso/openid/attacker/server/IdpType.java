/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sso.openid.attacker.server;

/**
 *
 * @author christiankossmann
 */
public enum IdpType {
    ATTACKER("Attacker"), ANALYZER("Analyzer");
    private String representation;
    
    private IdpType(String representation) {
        this.representation = representation;
    }

    @Override
    public String toString() {
        return representation;
    }
}
