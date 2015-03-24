/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package wsattacker.sso.openid.attacker.evaluation.strategies;

import java.util.concurrent.Callable;
import org.apache.commons.lang3.StringUtils;

/**
 *
 * @author christiankossmann
 */
public class StringSimilarityCallable implements Callable<Float>{

    private final String s1;
    private final String s2;
    
    public StringSimilarityCallable(String s1, String s2) {
        this.s1 = s1;
        this.s2 = s2;
    }
    
    @Override
    public Float call() throws Exception {
        //Instant startComputation = Instant.now();
        float result = StringUtils.getLevenshteinDistance(s1, s2);
        //Instant endComputation = Instant.now();
        //Duration duration = Duration.between(startComputation, endComputation);
        //System.out.println("length: " + s1.length() + "/" + s2.length() + ", duration: " + (duration.toNanos() / 1000000000) + " s, " + "result: " + result);
        //System.out.println("duration levenshtein: " + (duration.toNanos() / 1000000000) + " s");
        
        return result;
    }
}
