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
package wsattacker.sso.openid.attacker.evaluation.strategies;

import java.util.concurrent.Callable;
import org.apache.commons.lang3.StringUtils;

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
