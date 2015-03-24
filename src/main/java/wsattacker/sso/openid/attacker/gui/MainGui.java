package wsattacker.sso.openid.attacker.gui;

import java.awt.Dimension;
import java.awt.FileDialog;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.font.TextAttribute;
import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JSplitPane;
import javax.swing.KeyStroke;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.WindowConstants;
import org.apache.commons.lang3.SystemUtils;
import org.jdesktop.beansbinding.AutoBinding;
import org.jdesktop.beansbinding.BeanProperty;
import org.jdesktop.beansbinding.Binding;
import org.jdesktop.beansbinding.BindingGroup;
import org.jdesktop.beansbinding.Bindings;
import org.jdesktop.beansbinding.ELProperty;
import org.jdesktop.swingx.JXButton;
import org.jdesktop.swingx.JXTaskPane;
import org.jdesktop.swingx.JXTaskPaneContainer;
import org.jdesktop.swingx.VerticalLayout;
import wsattacker.sso.openid.attacker.bootstrap.Bootstrap;
import wsattacker.sso.openid.attacker.config.ToolConfiguration;
import wsattacker.sso.openid.attacker.config.XmlPersistenceError;
import wsattacker.sso.openid.attacker.config.XmlPersistenceHelper;
import wsattacker.sso.openid.attacker.controller.ServerController;
import wsattacker.sso.openid.attacker.server.IdpType;
import wsattacker.sso.openid.attacker.gui.attack.AttackOverviewGui;
import wsattacker.sso.openid.attacker.gui.discovery.html.HtmlConfigurationGui;
import wsattacker.sso.openid.attacker.gui.discovery.xrds.XrdsConfigurationGui;
import wsattacker.sso.openid.attacker.gui.evaluation.EvaluationGui;
import wsattacker.sso.openid.attacker.gui.evaluation.ReportGui;
import wsattacker.sso.openid.attacker.gui.log.LogGui;
import wsattacker.sso.openid.attacker.gui.server.ServerConfigurationGui;
import wsattacker.sso.openid.attacker.gui.user.AttackDataGui;
import wsattacker.sso.openid.attacker.gui.user.ValidDataGui;
import wsattacker.sso.openid.attacker.gui.utilities.XmlFileFilter;
import wsattacker.sso.openid.attacker.log.RequestLogger;

/**
 * This is the main GUI class which will be started from the JAR.
 */
public class MainGui extends javax.swing.JFrame implements ActionListener {
    
    private final JButton attackerIdpServerConfigurationButton = new JButton("Server Configuration");
    private final JButton attackerIdpHtmlDiscoveryButton = new JButton("HTML Discovery");
    private final JButton attackerIdpXrdsDiscoveryButton = new JButton("XRDS Discovery");
    private final JButton attackerIdpValidDataButton = new JButton("Valid Data");
    private final JButton attackerIdpAttackDataButton = new JButton("Attack Data");
    private final JButton attackerIdpAttackOverviewButton = new JButton("Attack Overview");
    
    private final JButton analyzerIdpServerConfigurationButton = new JButton("Server Configuration");
    private final JButton analyzerIdpHtmlDiscoveryButton = new JButton("HTML Discovery");
    private final JButton analyzerIdpXrdsDiscoveryButton = new JButton("XRDS Discovery");
    private final JButton analyzerIdpValidDataButton = new JButton("Valid Data");
    private final JButton analyzerIdpAttackDataButton = new JButton("Attack Data");
    private final JButton analyzerIdpAttackOverviewButton = new JButton("Parameter Overview");
    
    private final JButton evaluationButton = new JButton("Automated Analysis");
    private final JButton reportButton = new JButton("Reports");
    private final JButton logButton = new JButton("Log");
    
    private JButton lastPressedButton = attackerIdpServerConfigurationButton;
    private final Font defaultFont = UIManager.getDefaults().getFont("TextPane.font");
    private final Font boldUnderline;

    private final ServerConfigurationGui attackerIdpServerConfigurationGui = new ServerConfigurationGui();
    private final HtmlConfigurationGui attackerIdpHtmlConfigurationGui = new HtmlConfigurationGui();
    private final XrdsConfigurationGui attackerIdpXrdsConfigurationGui = new XrdsConfigurationGui();  
    private final ValidDataGui attackerIdpValidDataGui = new ValidDataGui();
    private final AttackDataGui attackerIdpAttackDataGui = new AttackDataGui();
    private final AttackOverviewGui attackerIdpAttackOverviewGui = new AttackOverviewGui(IdpType.ATTACKER);
    
    private final ServerConfigurationGui analyzerIdpServerConfigurationGui = new ServerConfigurationGui();
    private final HtmlConfigurationGui analyzerIdpHtmlConfigurationGui = new HtmlConfigurationGui();
    private final XrdsConfigurationGui analyzerIdpXrdsConfigurationGui = new XrdsConfigurationGui();  
    private final ValidDataGui analyzerIdpValidDataGui = new ValidDataGui();
    private final AttackDataGui analyzerIdpAttackDataGui = new AttackDataGui();
    private final AttackOverviewGui analyzerIdpAttackOverviewGui = new AttackOverviewGui(IdpType.ANALYZER);
    
    private final LogGui logGui = new LogGui();
    private final EvaluationGui evaluationGui = new EvaluationGui();
    private final ReportGui reportGui = new ReportGui();
    
    /**
     * Creates new form MainGui
     */
    public MainGui() {
        initComponents();
        
        analyzerIdpServerConfigurationGui.setIdp(IdpType.ANALYZER);
        analyzerIdpHtmlConfigurationGui.setIdp(IdpType.ANALYZER);
        analyzerIdpXrdsConfigurationGui.setIdp(IdpType.ANALYZER);
        analyzerIdpValidDataGui.setIdp(IdpType.ANALYZER);
        analyzerIdpAttackDataGui.setIdp(IdpType.ANALYZER);
        //analyzerIdpAttackOverviewGui.setIdp(IdpType.ANALYZER);
        
        Map<TextAttribute, Integer> fontAttributes = new HashMap<>();
        fontAttributes.put(TextAttribute.UNDERLINE, TextAttribute.LIGATURES_ON);
        boldUnderline = new Font(Font.SANS_SERIF, Font.BOLD, defaultFont.getSize()).deriveFont(fontAttributes);
        
        splitPane.setRightComponent(attackerIdpServerConfigurationGui);
        attackerIdpServerConfigurationButton.setFont(boldUnderline);
        
        // ========== Attacker IdP Task Pane ==========
        removeBackgroundFromButton(attackerIdpServerConfigurationButton);
        attackerIdpServerConfigurationButton.addActionListener(this);
        attackerIdpTaskPane.add(attackerIdpServerConfigurationButton);
        
        removeBackgroundFromButton(attackerIdpHtmlDiscoveryButton);
        attackerIdpHtmlDiscoveryButton.addActionListener(this);
        attackerIdpTaskPane.add(attackerIdpHtmlDiscoveryButton);
        
        removeBackgroundFromButton(attackerIdpXrdsDiscoveryButton);
        attackerIdpXrdsDiscoveryButton.addActionListener(this);
        attackerIdpTaskPane.add(attackerIdpXrdsDiscoveryButton);
        
        removeBackgroundFromButton(attackerIdpValidDataButton);
        attackerIdpValidDataButton.addActionListener(this);
        attackerIdpTaskPane.add(attackerIdpValidDataButton);
        
        removeBackgroundFromButton(attackerIdpAttackDataButton);
        attackerIdpAttackDataButton.addActionListener(this);
        attackerIdpTaskPane.add(attackerIdpAttackDataButton);
        
        removeBackgroundFromButton(attackerIdpAttackOverviewButton);
        attackerIdpAttackOverviewButton.addActionListener(this);
        attackerIdpTaskPane.add(attackerIdpAttackOverviewButton);
        
        // ========== Analyzer IdP Task Pane ==========
        removeBackgroundFromButton(analyzerIdpServerConfigurationButton);
        analyzerIdpServerConfigurationButton.addActionListener(this);
        analyzerIdpTaskPane.add(analyzerIdpServerConfigurationButton);
        
        removeBackgroundFromButton(analyzerIdpHtmlDiscoveryButton);
        analyzerIdpHtmlDiscoveryButton.addActionListener(this);
        analyzerIdpTaskPane.add(analyzerIdpHtmlDiscoveryButton);
        
        removeBackgroundFromButton(analyzerIdpXrdsDiscoveryButton);
        analyzerIdpXrdsDiscoveryButton.addActionListener(this);
        analyzerIdpTaskPane.add(analyzerIdpXrdsDiscoveryButton);
        
        removeBackgroundFromButton(analyzerIdpValidDataButton);
        analyzerIdpValidDataButton.addActionListener(this);
        analyzerIdpTaskPane.add(analyzerIdpValidDataButton);
        
        removeBackgroundFromButton(analyzerIdpAttackDataButton);
        analyzerIdpAttackDataButton.addActionListener(this);
        analyzerIdpTaskPane.add(analyzerIdpAttackDataButton);
        analyzerIdpAttackDataButton.setEnabled(false); // disable
        
        removeBackgroundFromButton(analyzerIdpAttackOverviewButton);
        analyzerIdpAttackOverviewButton.addActionListener(this);
        analyzerIdpTaskPane.add(analyzerIdpAttackOverviewButton);
        
        // ========== Evaluation Task Pane ==========
        removeBackgroundFromButton(evaluationButton);
        evaluationButton.addActionListener(this);
        evaluationTaskPane.add(evaluationButton);
        
        removeBackgroundFromButton(reportButton);
        reportButton.addActionListener(this);
        evaluationTaskPane.add(reportButton);
        
        // ========== Log Task Pane ==========
        removeBackgroundFromButton(logButton);
        logButton.addActionListener(this);
        logTaskPane.add(logButton);
    }   
    
    @Override
    public void actionPerformed(ActionEvent e) {
        JButton pressedButton = (JButton) e.getSource();
        //System.out.println("pressed button: " + pressedButton.getText());
        
        if (pressedButton == lastPressedButton) {
            // do nothing
            return;
        }        
        
        // remove selection from LAST pressed button
        lastPressedButton.setFont(defaultFont);
        lastPressedButton = pressedButton;
        
        // add selection to pressed button
        pressedButton.setFont(boldUnderline);
        
        JXTaskPane taskPaneOfPressedButton = (JXTaskPane) SwingUtilities.getAncestorOfClass(JXTaskPane.class, pressedButton);
        
        if (taskPaneOfPressedButton.getTitle().equals("Attacker IdP")) {

            switch (pressedButton.getText()) {
                case "Server Configuration":
                    splitPane.setRightComponent(attackerIdpServerConfigurationGui);
                    
                    break;
                case "HTML Discovery":
                    splitPane.setRightComponent(attackerIdpHtmlConfigurationGui);
                    break;
                case "XRDS Discovery":
                    splitPane.setRightComponent(attackerIdpXrdsConfigurationGui);
                    break;
                case "Valid Data":
                    splitPane.setRightComponent(attackerIdpValidDataGui);
                    break;
                case "Attack Data":
                    splitPane.setRightComponent(attackerIdpAttackDataGui);
                    break;
                case "Attack Overview":
                    splitPane.setRightComponent(attackerIdpAttackOverviewGui);
                    break;
            }
        } else {
            switch (pressedButton.getText()) {
                case "Server Configuration":
                    splitPane.setRightComponent(analyzerIdpServerConfigurationGui);
                    
                    break;
                case "HTML Discovery":
                    splitPane.setRightComponent(analyzerIdpHtmlConfigurationGui);
                    break;
                case "XRDS Discovery":
                    splitPane.setRightComponent(analyzerIdpXrdsConfigurationGui);
                    break;
                case "Valid Data":
                    splitPane.setRightComponent(analyzerIdpValidDataGui);
                    break;
                case "Attack Data":
                    splitPane.setRightComponent(analyzerIdpAttackDataGui);
                    break;
                case "Parameter Overview":
                    splitPane.setRightComponent(analyzerIdpAttackOverviewGui);
                    break;
                case "Automated Analysis":
                    splitPane.setRightComponent(evaluationGui);
                    break;
                case "Reports":
                    splitPane.setRightComponent(reportGui);
                    break;
                case "Log":
                    splitPane.setRightComponent(logGui);
                    break;
            }
        }
    }
    
    private void removeBackgroundFromButton(JXButton button) {
        button.setHorizontalAlignment(SwingConstants.LEFT);
        button.setBorder(null);
        button.setBorderPainted(false);
        button.setContentAreaFilled(false);
    }
    
    private void removeBackgroundFromButton(JButton button) {
        button.setHorizontalAlignment(SwingConstants.LEFT);
        button.setBorder(null);
        button.setBorderPainted(false);
        button.setContentAreaFilled(false);
    }

    /**
     * This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {
        bindingGroup = new BindingGroup();

        saveFileChooser = new JFileChooser();
        loadFileChooser = new JFileChooser();
        xmlFileFilter = new XmlFileFilter();
        controller = new ServerController();
        serverStatusToIconConverter = new ServerStatusToIconConverter();
        splitPane = new JSplitPane();
        jXTaskPaneContainer1 = new JXTaskPaneContainer();
        attackerIdpTaskPane = new JXTaskPane();
        analyzerIdpTaskPane = new JXTaskPane();
        evaluationTaskPane = new JXTaskPane();
        logTaskPane = new JXTaskPane();
        menuBar = new JMenuBar();
        fileMenu = new JMenu();
        saveItem = new JMenuItem();
        loadItem = new JMenuItem();
        jSeparator2 = new JPopupMenu.Separator();
        clearLogMenuItem = new JMenuItem();
        jSeparator1 = new JPopupMenu.Separator();
        exitNoConfigSave = new JMenuItem();
        exitAndSaveConfig = new JMenuItem();

        saveFileChooser.setDialogType(JFileChooser.SAVE_DIALOG);
        saveFileChooser.setFileFilter(xmlFileFilter);

        loadFileChooser.setFileFilter(xmlFileFilter);
        loadFileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);

        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            public void windowOpened(WindowEvent evt) {
                formWindowOpened(evt);
            }
            public void windowClosing(WindowEvent evt) {
                formWindowClosing(evt);
            }
        });

        splitPane.setBorder(null);
        splitPane.setDividerLocation(200);
        splitPane.setDividerSize(0);

        jXTaskPaneContainer1.setMinimumSize(new Dimension(200, 259));
        jXTaskPaneContainer1.setPreferredSize(new Dimension(200, 10));
        VerticalLayout verticalLayout1 = new VerticalLayout();
        verticalLayout1.setGap(14);
        jXTaskPaneContainer1.setLayout(verticalLayout1);

        attackerIdpTaskPane.setFocusable(false);
        attackerIdpTaskPane.setTitle("Attacker IdP");

        Binding binding = Bindings.createAutoBinding(AutoBinding.UpdateStrategy.READ_WRITE, controller, ELProperty.create("${attackerServer.status}"), attackerIdpTaskPane, BeanProperty.create("icon"));
        binding.setConverter(serverStatusToIconConverter);
        bindingGroup.addBinding(binding);

        jXTaskPaneContainer1.add(attackerIdpTaskPane);

        analyzerIdpTaskPane.setFocusable(false);
        analyzerIdpTaskPane.setTitle("Analyzer IdP");

        binding = Bindings.createAutoBinding(AutoBinding.UpdateStrategy.READ_WRITE, controller, ELProperty.create("${analyzerServer.status}"), analyzerIdpTaskPane, BeanProperty.create("icon"));
        binding.setConverter(serverStatusToIconConverter);
        bindingGroup.addBinding(binding);

        jXTaskPaneContainer1.add(analyzerIdpTaskPane);

        evaluationTaskPane.setFocusable(false);
        evaluationTaskPane.setTitle("Evaluation");
        jXTaskPaneContainer1.add(evaluationTaskPane);

        logTaskPane.setFocusable(false);
        logTaskPane.setTitle("Other");
        jXTaskPaneContainer1.add(logTaskPane);

        splitPane.setLeftComponent(jXTaskPaneContainer1);

        fileMenu.setMnemonic('F');
        fileMenu.setText("File");

        saveItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_S, InputEvent.ALT_MASK));
        saveItem.setText("Save Config");
        saveItem.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                saveItemActionPerformed(evt);
            }
        });
        fileMenu.add(saveItem);

        loadItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_L, InputEvent.ALT_MASK));
        loadItem.setText("Load Config");
        loadItem.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                loadItemActionPerformed(evt);
            }
        });
        fileMenu.add(loadItem);
        fileMenu.add(jSeparator2);

        clearLogMenuItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_MASK));
        clearLogMenuItem.setText("Clear Log");
        clearLogMenuItem.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                clearLogMenuItemActionPerformed(evt);
            }
        });
        fileMenu.add(clearLogMenuItem);
        fileMenu.add(jSeparator1);

        exitNoConfigSave.setText("Exit (without saving config)");
        exitNoConfigSave.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                exitNoConfigSaveActionPerformed(evt);
            }
        });
        fileMenu.add(exitNoConfigSave);

        exitAndSaveConfig.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_W, InputEvent.META_MASK));
        exitAndSaveConfig.setText("Exit");
        exitAndSaveConfig.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                exitAndSaveConfigActionPerformed(evt);
            }
        });
        fileMenu.add(exitAndSaveConfig);

        menuBar.add(fileMenu);

        setJMenuBar(menuBar);

        GroupLayout layout = new GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addComponent(splitPane, GroupLayout.DEFAULT_SIZE, 960, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addComponent(splitPane, GroupLayout.DEFAULT_SIZE, 528, Short.MAX_VALUE)
        );

        bindingGroup.bind();

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void saveItemActionPerformed(ActionEvent evt) {//GEN-FIRST:event_saveItemActionPerformed
        int returnVal = saveFileChooser.showSaveDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File saveFile = saveFileChooser.getSelectedFile();
            try {
                ToolConfiguration currentToolConfig = new ToolConfiguration();
                currentToolConfig.setAttackerConfig(controller.getAttackerConfig());
                currentToolConfig.setAnalyzerConfig(controller.getAnalyzerConfig());
                
                XmlPersistenceHelper.saveConfigToFile(saveFile, currentToolConfig);
            } catch (XmlPersistenceError ex) {
                Logger.getLogger(MainGui.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }//GEN-LAST:event_saveItemActionPerformed

    private void loadItemActionPerformed(ActionEvent evt) {//GEN-FIRST:event_loadItemActionPerformed
        FileDialog fd = new FileDialog(this, "Choose a file", FileDialog.LOAD);
        fd.setFile("*.xml");
        fd.setVisible(true);
        File[] files = fd.getFiles();
        
        if (files.length > 0) {
            File loadFile = files[0];
            
            try {
                ToolConfiguration currentToolConfig = new ToolConfiguration();
                currentToolConfig.setAttackerConfig(controller.getAttackerConfig());
                currentToolConfig.setAnalyzerConfig(controller.getAnalyzerConfig());
                
                XmlPersistenceHelper.mergeConfigFileToConfigObject(loadFile, currentToolConfig);
            } catch (XmlPersistenceError ex) {
                Logger.getLogger(MainGui.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        /*int returnVal = loadFileChooser.showOpenDialog(this);
                
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File loadFile = loadFileChooser.getSelectedFile();
            try {
                XmlPersistenceHelper.mergeConfigFileToConfigObject(loadFile, controller.getConfig());
            } catch (XmlPersistenceError ex) {
                Logger.getLogger(MainGui.class.getName()).log(Level.SEVERE, null, ex);
            }
        }*/
    }//GEN-LAST:event_loadItemActionPerformed

    private void formWindowClosing(WindowEvent evt) {//GEN-FIRST:event_formWindowClosing
        Bootstrap.onStop();
    }//GEN-LAST:event_formWindowClosing

    private void formWindowOpened(WindowEvent evt) {//GEN-FIRST:event_formWindowOpened
        Bootstrap.onStart();
    }//GEN-LAST:event_formWindowOpened

    private void exitNoConfigSaveActionPerformed(ActionEvent evt) {//GEN-FIRST:event_exitNoConfigSaveActionPerformed
        dispose();
    }//GEN-LAST:event_exitNoConfigSaveActionPerformed

    private void clearLogMenuItemActionPerformed(ActionEvent evt) {//GEN-FIRST:event_clearLogMenuItemActionPerformed
        RequestLogger.getInstance().clear();
    }//GEN-LAST:event_clearLogMenuItemActionPerformed

    private void exitAndSaveConfigActionPerformed(ActionEvent evt) {//GEN-FIRST:event_exitAndSaveConfigActionPerformed
        Bootstrap.onStop();
        dispose();
    }//GEN-LAST:event_exitAndSaveConfigActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) { 
        /*
         * Enhancing the GUI for OSX
         */
        // check, whether running on OSX       
        if (SystemUtils.IS_OS_MAC_OSX) {
            // use the correct menu bar on OSX
            System.setProperty("apple.laf.useScreenMenuBar", "true");
        
            // set name for the menu bar
            //System.setProperty("com.apple.mrj.application.apple.menu.about.name", "ImageRotator");
            
            // do not use the nimbus look and feel
        } else {
        
            /*
             * Set the Nimbus look and feel
             */
            //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
            /*
             * If Nimbus (introduced in Java SE 6) is not available, stay with the
             * default look and feel.
             * For details see
             * http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
             */
            try {
                for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                    if ("Nimbus".equals(info.getName())) {
                        javax.swing.UIManager.setLookAndFeel(info.getClassName());
                        break;
                    }
                }
            } catch (ClassNotFoundException ex) {
                java.util.logging.Logger.getLogger(MainGui.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
            } catch (InstantiationException ex) {
                java.util.logging.Logger.getLogger(MainGui.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
            } catch (IllegalAccessException ex) {
                java.util.logging.Logger.getLogger(MainGui.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
            } catch (javax.swing.UnsupportedLookAndFeelException ex) {
                java.util.logging.Logger.getLogger(MainGui.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
            }
            //</editor-fold>
        }
        
        /*
         * Create and display the form
         */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new MainGui().setVisible(true);
            }
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private JXTaskPane analyzerIdpTaskPane;
    private JXTaskPane attackerIdpTaskPane;
    private JMenuItem clearLogMenuItem;
    private ServerController controller;
    private JXTaskPane evaluationTaskPane;
    private JMenuItem exitAndSaveConfig;
    private JMenuItem exitNoConfigSave;
    private JMenu fileMenu;
    private JPopupMenu.Separator jSeparator1;
    private JPopupMenu.Separator jSeparator2;
    private JXTaskPaneContainer jXTaskPaneContainer1;
    private JFileChooser loadFileChooser;
    private JMenuItem loadItem;
    private JXTaskPane logTaskPane;
    private JMenuBar menuBar;
    private JFileChooser saveFileChooser;
    private JMenuItem saveItem;
    private ServerStatusToIconConverter serverStatusToIconConverter;
    private JSplitPane splitPane;
    private XmlFileFilter xmlFileFilter;
    private BindingGroup bindingGroup;
    // End of variables declaration//GEN-END:variables
}
