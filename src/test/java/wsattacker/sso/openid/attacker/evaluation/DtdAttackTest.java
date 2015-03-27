/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sso.openid.attacker.evaluation;

import static org.junit.Assert.assertEquals;
import org.junit.Test;
import wsattacker.sso.openid.attacker.evaluation.attack.DtdAttack;

/**
 *
 * @author christiankossmann
 */
public class DtdAttackTest {
    
    @Test
    public void testAppendPathToUrlWithSlash() {
        String url = "http://my-idp.xyz/";
        String path = "xxe";
        
        ServiceProvider sp = new ServiceProvider(url);
        DtdAttack dtdAttack = new DtdAttack(sp);
        
        assertEquals(dtdAttack.addPathToUrl(path, url), "http://my-idp.xyz/xxe");
    }
    
    @Test
    public void testAppendPathToUrlWithoutSlash() {
        String url = "http://my-idp.xyz";
        String path = "xxe";
        
        ServiceProvider sp = new ServiceProvider(url);
        DtdAttack dtdAttack = new DtdAttack(sp);
        
        assertEquals(dtdAttack.addPathToUrl(path, url), "http://my-idp.xyz/xxe");
    }
    
}
