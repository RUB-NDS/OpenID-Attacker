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
package wsattacker.sso.openid.attacker.evaluation.training;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import javax.swing.JProgressBar;
import javax.swing.SwingWorker;
import org.apache.commons.lang3.time.StopWatch;
import wsattacker.sso.openid.attacker.evaluation.EvaluationResult;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider.User;
import wsattacker.sso.openid.attacker.evaluation.training.Training.ErrorType;

public class TrainingWorker extends SwingWorker<Void, TrainingResult> {

    private final ServiceProvider serviceProvider;
    private final JProgressBar progressBar;
    private final EvaluationResult evaluationResult;
    
    private final int numberOfTrainingSamples = 2;
    private final int progressStep = 100 / (3*numberOfTrainingSamples);
    private int progress = 0;
    
    private final List<TrainingResult> trainingResults = new ArrayList<>(numberOfTrainingSamples);
    
    private final CountDownLatch actuallyFinishedLatch = new CountDownLatch(1);

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
            
            if (isCancelled()) {
                System.out.println("cancelled");
                actuallyFinishedLatch.countDown();
                return null;
            }
            
            // Victim
            trainingResult = training.performSuccessfulLogin(User.VICTIM);
            serviceProvider.addVictimSuccessPageSource(trainingResult.getLoginResult().getPageSource());
            
            publish(trainingResult);
            
            if (isCancelled()) {
                System.out.println("cancelled");
                actuallyFinishedLatch.countDown();
                return null;
            }
                        
            // Error
            trainingResult = training.performUnsuccessfulLogin(errors[i]);
            serviceProvider.addFailurePageSource(trainingResult.getLoginResult().getPageSource());
            
            publish(trainingResult);
            
            if (isCancelled()) {
                System.out.println("cancelled");
                actuallyFinishedLatch.countDown();
                return null;
            }
        }
        
        stopWatch.stop();
        evaluationResult.addInvestigationTime(stopWatch.getTime()/1000);
        
        return null;
    } 

    @Override
    protected void process(List<TrainingResult> results) {
        if (isCancelled()) {
            return;
        }
        
        for (TrainingResult result: results) {
            progress += progressStep;
            progressBar.setValue(progress);
            
            trainingResults.add(result);
        }
    }
    
    public void awaitActualCompletion() throws InterruptedException {
        actuallyFinishedLatch.await();
    }

    @Override
    protected void done() {
        if (isCancelled()) {
            return;
        }
        
        progressBar.setValue(100);
        evaluationResult.addTrainingResults(trainingResults);
    }
}