/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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

/**
 *
 * @author christian
 */
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