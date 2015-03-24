/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sso.openid.attacker.evaluation.training;

import java.util.ArrayList;
import java.util.List;
import javax.swing.JProgressBar;
import javax.swing.SwingWorker;
import org.apache.commons.lang3.time.StopWatch;
import wsattacker.sso.openid.attacker.evaluation.EvaluationResult;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider.User;
import wsattacker.sso.openid.attacker.evaluation.training.Training.ErrorType;

/**
 *
 * @author christiankossmann
 */
public class TrainingWorker extends SwingWorker<Void, TrainingResult> {

    private final ServiceProvider serviceProvider;
    private final JProgressBar progressBar;
    private final EvaluationResult evaluationResult;
    
    private final int numberOfTrainingSamples = 3;
    private final int progressStep = 100 / (3*numberOfTrainingSamples);
    private int progress = 0;
    
    private final List<TrainingResult> trainingResults = new ArrayList<>(numberOfTrainingSamples);

    public TrainingWorker(ServiceProvider servideProvider, JProgressBar progressBar, EvaluationResult evaluationResult) {
        this.serviceProvider = servideProvider;
        this.progressBar = progressBar;      
        this.evaluationResult = evaluationResult;
    }
    
    @Override
    protected Void doInBackground() throws Exception {
        StopWatch stopWatch = new StopWatch();
        stopWatch.start();
        
        Training training = new Training(serviceProvider);
        ErrorType errors[] = ErrorType.values();       
        
        for (int i = 0; i < numberOfTrainingSamples; i++) {
            // Attacker
            TrainingResult trainingResult = training.performSuccessfulLogin(User.ATTACKER);
            serviceProvider.addAttackerSuccessPageSource(trainingResult.getLoginResult().getPageSource());
            
            publish(trainingResult);
            
            // Victim
            trainingResult = training.performSuccessfulLogin(User.VICTIM);
            serviceProvider.addVictimSuccessPageSource(trainingResult.getLoginResult().getPageSource());
            
            publish(trainingResult);
                        
            // Error
            trainingResult = training.performUnsuccessfulLogin(errors[i]);
            serviceProvider.addFailurePageSource(trainingResult.getLoginResult().getPageSource());
            
            publish(trainingResult);
        }
        
        stopWatch.stop();
        evaluationResult.addInvestigationTime(stopWatch.getTime()/1000);
        
        return null;
    } 

    @Override
    protected void process(List<TrainingResult> results) {
        for (TrainingResult result: results) {
            progress += progressStep;
            progressBar.setValue(progress);
            
            trainingResults.add(result);
        }
    }

    @Override
        protected void done() {
        progressBar.setValue(100);
        
        evaluationResult.addTrainingResults(trainingResults);
    }
}