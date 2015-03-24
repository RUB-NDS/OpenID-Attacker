/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sso.openid.attacker.config;

import javax.xml.bind.annotation.XmlRootElement;
import wsattacker.sso.openid.attacker.composition.AbstractBean;

/**
 *
 * @author christiankossmann
 */

@XmlRootElement(name = "ToolConfiguration")
public class ToolConfiguration extends AbstractBean {
    
    private OpenIdServerConfiguration attackerConfig;
    private OpenIdServerConfiguration analyzerConfig;

    public static final String PROP_ATTACKERCONFIG = "attackerConfig";
    public static final String PROP_ANALYZERCONFIG = "analyzerConfig";
        
    public ToolConfiguration() {
        
    }
    
    /**
     * Get the value of analyzerConfig
     *
     * @return the value of analyzerConfig
     */
    public OpenIdServerConfiguration getAnalyzerConfig() {
        return analyzerConfig;
    }

    /**
     * Set the value of analyzerConfig
     *
     * @param analyzerConfig new value of analyzerConfig
     */
    public void setAnalyzerConfig(OpenIdServerConfiguration analyzerConfig) {
        OpenIdServerConfiguration oldAnalyzerConfig = this.analyzerConfig;
        this.analyzerConfig = analyzerConfig;
        firePropertyChange(PROP_ANALYZERCONFIG, oldAnalyzerConfig, analyzerConfig);
    }

    /**
     * Get the value of attackerConfig
     *
     * @return the value of attackerConfig
     */
    public OpenIdServerConfiguration getAttackerConfig() {
        return attackerConfig;
    }

    /**
     * Set the value of attackerConfig
     *
     * @param attackerConfig new value of attackerConfig
     */
    public void setAttackerConfig(OpenIdServerConfiguration attackerConfig) {
        OpenIdServerConfiguration oldAttackerConfig = this.attackerConfig;
        this.attackerConfig = attackerConfig;
        firePropertyChange(PROP_ATTACKERCONFIG, oldAttackerConfig, attackerConfig);
    }   
}
