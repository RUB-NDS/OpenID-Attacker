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
package wsattacker.sso.openid.attacker.gui.evaluation;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;
import javax.swing.SwingWorker;
import javax.swing.SwingWorker.StateValue;
import static javax.swing.SwingWorker.StateValue.DONE;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import wsattacker.sso.openid.attacker.config.OpenIdServerConfiguration;
import wsattacker.sso.openid.attacker.controller.ServerController;
import wsattacker.sso.openid.attacker.evaluation.EvaluationResult;
import wsattacker.sso.openid.attacker.evaluation.EvaluationResultStore;
import wsattacker.sso.openid.attacker.evaluation.attack.AttackWorker;
import wsattacker.sso.openid.attacker.evaluation.ExecutorServices;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider.User;
import wsattacker.sso.openid.attacker.evaluation.training.TrainingWorker;

public class EvaluationGui extends javax.swing.JPanel {

    private ServiceProvider serviceProvider;    
    private SwingWorker<Void, ?> currentWorker;

    /**
     * Creates new form TestingGui
     */
    public EvaluationGui() {
        initComponents();
        
        serviceProviderTextField.getDocument().addDocumentListener(new DocumentListener() {

            @Override
            public void insertUpdate(DocumentEvent e) {
                serviceProviderTextFieldChanged();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                serviceProviderTextFieldChanged();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                serviceProviderTextFieldChanged();
            }
        });
        
        victimTable.getColumnModel().getColumn(0).setPreferredWidth(125);
        victimTable.getColumnModel().getColumn(1).setPreferredWidth(300);
        attackerTable.getColumnModel().getColumn(0).setPreferredWidth(125);
        attackerTable.getColumnModel().getColumn(1).setPreferredWidth(300);
        
        setTrainined(false);
        showProgressBar(false);
    }
    
    private void serviceProviderTextFieldChanged() {
        setTrainined(false);
    }
    
    private void setTrainined(boolean value) {
        if (value) {
            trainButton.setText("Retrain");
        } else {
            trainButton.setText("Train");
        }
        
        
        trainedLabel.setVisible(value);
        notTrainedLabel.setVisible(!value);
        saveTrainingButton.setEnabled(value);
        
        performAttackButton.setEnabled(value);
        performAllAttacksButton.setEnabled(value);
        attackComboBox.setEnabled(value);
    }
    
    private void enableAllButtons(boolean value) {
        trainButton.setEnabled(value);
        loadTrainingButton.setEnabled(value);
        saveTrainingButton.setEnabled(value);
        
        performAttackButton.setEnabled(value);
        performAllAttacksButton.setEnabled(value);
        attackComboBox.setEnabled(value);
        serviceProviderTextField.setEnabled(value);
        /*attackerOpenIdTextField.setEnabled(value);
        attackerUsernameTextField.setEnabled(value);
        victimOpenIdTextField.setEnabled(value);
        victimUsernameTextField.setEnabled(value);*/
    }
    
    private void showProgressBar(boolean value) {
        currentActionProgressBar.setVisible(value);
        currentActionProgressBar.setValue(0);
        currentActionLabel.setVisible(value);
        cancelButton.setVisible(value);
    } 

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {
        bindingGroup = new org.jdesktop.beansbinding.BindingGroup();

        serverController1 = new wsattacker.sso.openid.attacker.controller.ServerController();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();
        jScrollPane3 = new javax.swing.JScrollPane();
        jTable2 = new javax.swing.JTable();
        currentActionProgressBar = new javax.swing.JProgressBar();
        currentActionLabel = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        serviceProviderTextField = new javax.swing.JTextField();
        trainButton = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();
        saveTrainingButton = new javax.swing.JButton();
        loadTrainingButton = new javax.swing.JButton();
        attackComboBox = new javax.swing.JComboBox();
        performAttackButton = new javax.swing.JButton();
        performAllAttacksButton = new javax.swing.JButton();
        jLabel9 = new javax.swing.JLabel();
        trainedLabel = new javax.swing.JLabel();
        notTrainedLabel = new javax.swing.JLabel();
        title = new javax.swing.JLabel();
        jScrollPane4 = new javax.swing.JScrollPane();
        victimTable = new javax.swing.JTable();
        jScrollPane5 = new javax.swing.JScrollPane();
        attackerTable = new javax.swing.JTable();
        cancelButton = new javax.swing.JButton();

        jTable1.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        jScrollPane1.setViewportView(jTable1);

        jTable2.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        jScrollPane3.setViewportView(jTable2);

        currentActionProgressBar.setStringPainted(true);

        jLabel1.setText("Service Provider");

        serviceProviderTextField.setText("https://example.com/login");
        serviceProviderTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                serviceProviderTextFieldActionPerformed(evt);
            }
        });
        serviceProviderTextField.addPropertyChangeListener(new java.beans.PropertyChangeListener() {
            public void propertyChange(java.beans.PropertyChangeEvent evt) {
                serviceProviderTextFieldPropertyChange(evt);
            }
        });

        trainButton.setText("Train");
        trainButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                trainButtonActionPerformed(evt);
            }
        });

        jLabel3.setFont(new java.awt.Font("Lucida Grande", 1, 18)); // NOI18N
        jLabel3.setText("Victim");

        jLabel5.setFont(new java.awt.Font("Lucida Grande", 1, 18)); // NOI18N
        jLabel5.setText("Attacker");

        jLabel8.setFont(new java.awt.Font("Lucida Grande", 1, 18)); // NOI18N
        jLabel8.setText("Attacks");

        saveTrainingButton.setText("Save Training");
        saveTrainingButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveTrainingButtonActionPerformed(evt);
            }
        });

        loadTrainingButton.setText("Load Training");
        loadTrainingButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadTrainingButtonActionPerformed(evt);
            }
        });

        attackComboBox.setMaximumRowCount(12);
        attackComboBox.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "Signature Exclusion", "Replay", "Token Recipient Confusion", "ID Spoofing", "Key Confusion", "Discovery Spoofing", "Parameter Forgery", "XXE/DTD", "Malicious Metadata", "Same IdP Delegation" }));

        performAttackButton.setText("Perform Attack");
        performAttackButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                performAttackButtonActionPerformed(evt);
            }
        });

        performAllAttacksButton.setText("Perform All Attacks");
        performAllAttacksButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                performAllAttacksButtonActionPerformed(evt);
            }
        });

        jLabel9.setFont(new java.awt.Font("Lucida Grande", 1, 18)); // NOI18N
        jLabel9.setText("Training");

        trainedLabel.setFont(new java.awt.Font("Lucida Grande", 1, 18)); // NOI18N
        trainedLabel.setForeground(new java.awt.Color(67, 139, 19));
        trainedLabel.setText("(✔)");

        notTrainedLabel.setFont(new java.awt.Font("Lucida Grande", 1, 18)); // NOI18N
        notTrainedLabel.setForeground(new java.awt.Color(255, 0, 0));
        notTrainedLabel.setText("(✗)");

        title.setFont(new java.awt.Font("Dialog", 1, 24)); // NOI18N
        title.setText("Automated Analysis");

        org.jdesktop.beansbinding.ELProperty eLProperty = org.jdesktop.beansbinding.ELProperty.create("${analyzerConfig.validUser.dataList}");
        org.jdesktop.swingbinding.JTableBinding jTableBinding = org.jdesktop.swingbinding.SwingBindings.createJTableBinding(org.jdesktop.beansbinding.AutoBinding.UpdateStrategy.READ_WRITE, serverController1, eLProperty, victimTable);
        org.jdesktop.swingbinding.JTableBinding.ColumnBinding columnBinding = jTableBinding.addColumnBinding(org.jdesktop.beansbinding.ELProperty.create("${name}"));
        columnBinding.setColumnName("Name");
        columnBinding.setColumnClass(String.class);
        columnBinding = jTableBinding.addColumnBinding(org.jdesktop.beansbinding.ELProperty.create("${value}"));
        columnBinding.setColumnName("Value");
        columnBinding.setColumnClass(String.class);
        bindingGroup.addBinding(jTableBinding);
        jTableBinding.bind();
        jScrollPane4.setViewportView(victimTable);

        eLProperty = org.jdesktop.beansbinding.ELProperty.create("${attackerConfig.validUser.dataList}");
        jTableBinding = org.jdesktop.swingbinding.SwingBindings.createJTableBinding(org.jdesktop.beansbinding.AutoBinding.UpdateStrategy.READ_WRITE, serverController1, eLProperty, attackerTable);
        columnBinding = jTableBinding.addColumnBinding(org.jdesktop.beansbinding.ELProperty.create("${name}"));
        columnBinding.setColumnName("Name");
        columnBinding.setColumnClass(String.class);
        columnBinding = jTableBinding.addColumnBinding(org.jdesktop.beansbinding.ELProperty.create("${value}"));
        columnBinding.setColumnName("Value");
        columnBinding.setColumnClass(String.class);
        bindingGroup.addBinding(jTableBinding);
        jTableBinding.bind();
        jScrollPane5.setViewportView(attackerTable);

        cancelButton.setText("Cancel");
        cancelButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(12, 12, 12)
                        .addComponent(jLabel3))
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, 312, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel5)
                    .addComponent(jScrollPane5, javax.swing.GroupLayout.PREFERRED_SIZE, 322, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(title)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(saveTrainingButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(loadTrainingButton)
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addGap(6, 6, 6)
                                .addComponent(jLabel1)
                                .addGap(18, 18, 18)
                                .addComponent(serviceProviderTextField))
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addGap(6, 6, 6)
                                        .addComponent(jLabel9)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(trainedLabel)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(notTrainedLabel))
                                    .addComponent(trainButton))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(attackComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, 237, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                            .addComponent(performAllAttacksButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                            .addComponent(performAttackButton, javax.swing.GroupLayout.PREFERRED_SIZE, 166, javax.swing.GroupLayout.PREFERRED_SIZE)))
                                    .addGroup(layout.createSequentialGroup()
                                        .addGap(6, 6, 6)
                                        .addComponent(jLabel8))))
                            .addComponent(currentActionLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(currentActionProgressBar, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(cancelButton)))
                        .addContainerGap())))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(title)
                        .addGap(10, 10, 10)
                        .addComponent(jLabel3))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(42, 42, 42)
                        .addComponent(jLabel5)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 84, Short.MAX_VALUE)
                    .addComponent(jScrollPane5, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE))
                .addGap(12, 12, 12)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(serviceProviderTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel9)
                            .addComponent(trainedLabel)
                            .addComponent(notTrainedLabel))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(35, 35, 35)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(loadTrainingButton)
                                    .addComponent(saveTrainingButton)))
                            .addComponent(trainButton)))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel8)
                        .addGap(7, 7, 7)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(performAttackButton)
                            .addComponent(attackComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(performAllAttacksButton)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 129, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(currentActionProgressBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(5, 5, 5))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(currentActionLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 21, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(cancelButton))))
        );

        bindingGroup.bind();
    }// </editor-fold>//GEN-END:initComponents

    private void trainButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_trainButtonActionPerformed
        serviceProvider = new ServiceProvider(serviceProviderTextField.getText());
        
        EvaluationResult evaluationResult = new EvaluationResult(new Date(), serviceProviderTextField.getText());
        EvaluationResultStore evaluationResultStore = EvaluationResultStore.getEvaluationResultStore();
        evaluationResultStore.addEvaluationResult(evaluationResult);
        
        enableAllButtons(false);
        showProgressBar(true);
        
        TrainingWorker trainingWorker = new TrainingWorker(serviceProvider, currentActionProgressBar, evaluationResult);      
        
        trainingWorker.addPropertyChangeListener((PropertyChangeEvent evt1) -> {
            if (evt1.getPropertyName().equals("state")) {
                if ((StateValue) evt1.getNewValue() == DONE) {
                    boolean cancelled = currentWorker.isCancelled();
                    System.out.println("cancelled: " + cancelled);
                    
                    if (cancelled) {
                        try {
                            ((TrainingWorker)currentWorker).awaitActualCompletion();
                        } catch (InterruptedException ex) {
                            Logger.getLogger(EvaluationGui.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                    
                    enableAllButtons(true);
                    setTrainined(!cancelled);
                    showProgressBar(false);
                }
            }
            System.out.println(evt1.getPropertyName() + " from " + evt1.getOldValue() + " to " + evt1.getNewValue());
        });
        trainingWorker.execute();
        
        currentWorker = trainingWorker;
    }//GEN-LAST:event_trainButtonActionPerformed

    private void serviceProviderTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_serviceProviderTextFieldActionPerformed
        setTrainined(false);
        
        // new website -> clear all parameters
        ServerController controller = new ServerController();
        controller.getServer().clearParameters();
    }//GEN-LAST:event_serviceProviderTextFieldActionPerformed

    private void serviceProviderTextFieldPropertyChange(java.beans.PropertyChangeEvent evt) {//GEN-FIRST:event_serviceProviderTextFieldPropertyChange
        // TODO add your handling code here:
    }//GEN-LAST:event_serviceProviderTextFieldPropertyChange

    private void saveTrainingButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveTrainingButtonActionPerformed
        String fileName = (String) JOptionPane.showInputDialog("Please enter a file name: ");

        if (fileName == null) {
            JOptionPane.showMessageDialog(null, "Error: cannot save training data!");
            return;
        }
        
        try {
            File file = new File("training/" + fileName + ".ser");
            file.getParentFile().mkdirs();

            OutputStream fos = Files.newOutputStream(file.toPath());
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(this.serviceProvider);
        } catch (IOException e) {
            
        }
        
        JOptionPane.showMessageDialog(null, "Training data was saved successfully.");
    }//GEN-LAST:event_saveTrainingButtonActionPerformed

    private void loadTrainingButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadTrainingButtonActionPerformed
       
        HashSet<String> fileNames = new HashSet<>();
        try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(Paths.get("training"))) {
            for (Path path : directoryStream) {

                if (!path.getFileName().toString().startsWith(".")) {
                    fileNames.add(path.getFileName().toString().substring(0, path.getFileName().toString().length()));
                }
            }
        } catch (IOException ex) {
            
        }
        
        if (fileNames.isEmpty()) {
            JOptionPane.showMessageDialog(null, "Error: No files found!");
            return;
        }

        String[] fileNamesOptions = fileNames.toArray(new String[fileNames.size()]);

        String fileName = (String) JOptionPane.showInputDialog(null,
                "File name",
                "Please choose a filename",
                JOptionPane.QUESTION_MESSAGE,
                null, fileNamesOptions,
                fileNamesOptions[0]);

        if (fileName == null) {
            JOptionPane.showMessageDialog(null, "Error: cannot load training data!");
            return;
        }
        
        try {
            InputStream fis = Files.newInputStream(Paths.get("training/" + fileName));
            ObjectInputStream ois = new ObjectInputStream(fis);
            
            this.serviceProvider = (ServiceProvider) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.out.println(e);
        }
        
        if (this.serviceProvider == null) {
            JOptionPane.showMessageDialog(null, "Error: cannot read file!");
            return;
        }

        this.serviceProvider.login(User.ATTACKER);
        this.serviceProvider.login(User.VICTIM);
        
        // set text values of GUI
        this.serviceProviderTextField.setText(this.serviceProvider.getUrl());
        
        for (Map.Entry<String, String> entry : serviceProvider.getVictimData().entrySet()) {
            OpenIdServerConfiguration.getAnalyzerInstance().getValidUser().set(entry.getKey(), entry.getValue());
        }
        
        for (Map.Entry<String, String> entry : serviceProvider.getAttackerData().entrySet()) {
            OpenIdServerConfiguration.getAttackerInstance().getValidUser().set(entry.getKey(), entry.getValue());
        }
        
        
        /*this.attackerOpenIdTextField.setText(this.serviceProvider.getAttackerOpenId());
        this.attackerUsernameTextField.setText(this.serviceProvider.getAttackerUsername());
        this.victimOpenIdTextField.setText(this.serviceProvider.getVictimOpenId());
        this.victimUsernameTextField.setText(this.serviceProvider.getVictimUsername());*/
        
        EvaluationResult evaluationResult = new EvaluationResult(new Date(), serviceProviderTextField.getText());
        EvaluationResultStore evaluationResultStore = EvaluationResultStore.getEvaluationResultStore();
        evaluationResultStore.addEvaluationResult(evaluationResult);
        
        setTrainined(true);
        JOptionPane.showMessageDialog(null, "Training data was loaded successfully.");

    }//GEN-LAST:event_loadTrainingButtonActionPerformed

    private void performAttackButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_performAttackButtonActionPerformed
        String attackName = (String)attackComboBox.getSelectedItem();
        
        currentActionProgressBar.setIndeterminate(true);
        performAttackButton.setEnabled(false);
        currentActionLabel.setText("Performing " + attackName + " Attack...");
        enableAllButtons(false);
        showProgressBar(true);
                
        AttackWorker attackWorker = new AttackWorker(attackName, serviceProvider, EvaluationResultStore.getEvaluationResultStore().getLatestEvaluationResult());
        attackWorker.addPropertyChangeListener((PropertyChangeEvent evt1) -> {
            if (evt1.getPropertyName().equals("state")) {
                if ((StateValue) evt1.getNewValue() == DONE) {
                    currentActionProgressBar.setIndeterminate(false);
                    performAttackButton.setEnabled(true);
                    currentActionLabel.setText("");
                    enableAllButtons(true);
                    setTrainined(true);
                    showProgressBar(false);
                }
            }
        });
        
        attackWorker.execute();
    }//GEN-LAST:event_performAttackButtonActionPerformed

    private void performAllAttacksButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_performAllAttacksButtonActionPerformed
        String[] attackNames = {
            "Signature Exclusion",
            "Replay",
            "Token Recipient Confusion",
            "ID Spoofing",
            "Key Confusion",
            "Parameter Forgery",
            "Discovery Spoofing",
            "XXE/DTD",
            "Malicious Metadata",
            "Same IdP Delegation"
        };
            
        currentActionProgressBar.setIndeterminate(true);
        performAttackButton.setEnabled(false);
        performAllAttacksButton.setEnabled(false);
        currentActionLabel.setText("Performing all attacks...");
        enableAllButtons(false);
        showProgressBar(true);
        
        for (String attackName: attackNames) {
            AttackWorker attackWorker = new AttackWorker(attackName, serviceProvider, EvaluationResultStore.getEvaluationResultStore().getLatestEvaluationResult());
            
            if (attackName.equals("Same IdP Delegation")) {
                attackWorker.addPropertyChangeListener(new PropertyChangeListener() {

                    @Override
                    public void propertyChange(PropertyChangeEvent evt) {
                        if (evt.getPropertyName().equals("state")) {
                            if ((StateValue) evt.getNewValue() == DONE) {
                                currentActionProgressBar.setIndeterminate(false);
                                performAttackButton.setEnabled(true);
                                performAllAttacksButton.setEnabled(true);
                                currentActionLabel.setText("");
                                enableAllButtons(true);
                                setTrainined(true);
                                showProgressBar(false);
                            }
                        }
                    }
                });
            }
            
            ExecutorServices.getSingleThreadExecutor().execute(attackWorker);
        }
    }//GEN-LAST:event_performAllAttacksButtonActionPerformed

    private void cancelButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelButtonActionPerformed
        if (currentWorker != null) {
            currentWorker.cancel(false);
        }
    }//GEN-LAST:event_cancelButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JComboBox attackComboBox;
    private javax.swing.JTable attackerTable;
    private javax.swing.JButton cancelButton;
    private javax.swing.JLabel currentActionLabel;
    private javax.swing.JProgressBar currentActionProgressBar;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JScrollPane jScrollPane5;
    private javax.swing.JTable jTable1;
    private javax.swing.JTable jTable2;
    private javax.swing.JButton loadTrainingButton;
    private javax.swing.JLabel notTrainedLabel;
    private javax.swing.JButton performAllAttacksButton;
    private javax.swing.JButton performAttackButton;
    private javax.swing.JButton saveTrainingButton;
    private wsattacker.sso.openid.attacker.controller.ServerController serverController1;
    private javax.swing.JTextField serviceProviderTextField;
    private javax.swing.JLabel title;
    private javax.swing.JButton trainButton;
    private javax.swing.JLabel trainedLabel;
    private javax.swing.JTable victimTable;
    private org.jdesktop.beansbinding.BindingGroup bindingGroup;
    // End of variables declaration//GEN-END:variables
}
