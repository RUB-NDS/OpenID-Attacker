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
package wsattacker.sso.openid.attacker.evaluation;

import wsattacker.sso.openid.attacker.evaluation.training.TrainingResult;
import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import wsattacker.sso.openid.attacker.evaluation.attack.AttackResult;

public class EvaluationResult implements Serializable {
    private final Date date;
    private final String url;
    private int investigationTime = 0;
    
    private List<TrainingResult> trainingResults;
    private final Map<String, List<AttackResult>> mapOfAttackResult = new HashMap<>();
    
    public EvaluationResult(Date date, String url) {
        this.date = date;
        this.url = url;
    } 

    public String getUrl() {
        return url;
    }

    public Date getDate() {
        return date;
    }
    
    public String getFormattedDate() {
        return new SimpleDateFormat("yyyy-MM-dd - HH:mm:ss").format(date);
    }
    
    public void addTrainingResults(List<TrainingResult> trainingResults) {
        this.trainingResults = trainingResults;
    }

    public List<TrainingResult> getTrainingResults() {
        return trainingResults;
    }
    
    public void addAttackResults(String attackName, List<AttackResult> attackResults) {
        mapOfAttackResult.put(attackName, attackResults);
    }

    public Map<String, List<AttackResult>> getMapOfAttackResult() {
        return mapOfAttackResult;
    }

    @Override
    public String toString() {
        return url + " - " + date;
    }
    
    public void addInvestigationTime(long time) {
        investigationTime += time;
    }

    public int getInvestigationTime() {
        return investigationTime;
    }

    public String getInvestigationTimeFormatted() {
        int seconds = investigationTime % 60;
        int minutes = investigationTime / 60;
        
        return minutes + "m " + seconds + "s";
    }
}