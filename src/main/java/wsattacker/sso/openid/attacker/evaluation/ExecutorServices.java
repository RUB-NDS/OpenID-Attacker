/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sso.openid.attacker.evaluation;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 *
 * @author christiankossmann
 */
public class ExecutorServices {
    private static ExecutorService multiThreadExecutor;
    private static ExecutorService singleThreadExecutor;
    
    private ExecutorServices() {
        
    }
    
    public static ExecutorService getMultiThreadExecutor() {
        if (multiThreadExecutor == null) {
            multiThreadExecutor = Executors.newCachedThreadPool();
        }
        
        return multiThreadExecutor;
    }
    
    public static ExecutorService getSingleThreadExecutor() {
        if (singleThreadExecutor == null) {
            singleThreadExecutor = Executors.newSingleThreadExecutor();
        }
        
        return singleThreadExecutor;
    }
}
