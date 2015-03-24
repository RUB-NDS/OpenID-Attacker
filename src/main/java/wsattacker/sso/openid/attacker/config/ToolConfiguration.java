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
