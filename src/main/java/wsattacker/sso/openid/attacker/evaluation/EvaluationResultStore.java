/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sso.openid.attacker.evaluation;

import java.util.ArrayList;
import java.util.List;
import org.jdesktop.observablecollections.ObservableCollections;
import org.jdesktop.observablecollections.ObservableList;

/**
 *
 * @author christian
 */
public class EvaluationResultStore {
    private static EvaluationResultStore INSTANCE;
    
    private final ObservableList<EvaluationResult> evaluationResults = ObservableCollections.observableList(new ArrayList<EvaluationResult>());
    
    private EvaluationResultStore() {
        
    }
    
    public static EvaluationResultStore getEvaluationResultStore() {
        if (INSTANCE == null) {
            INSTANCE = new EvaluationResultStore();
        }
        
        return INSTANCE;
    }
    
    public void addEvaluationResult(EvaluationResult result) {
        evaluationResults.add(result);
    }
    
    public EvaluationResult getLatestEvaluationResult() {
        return evaluationResults.get(evaluationResults.size()-1);
    }
    
    public List<EvaluationResult> getEvaluationResults() {
        return evaluationResults;
    }

    public void setEvaluationResults(List<EvaluationResult> evaluationResults) {
        
    }
}
