package wsattacker.sso.openid.attacker.bootstrap;

import java.io.File;
import java.util.List;
import org.apache.log4j.Logger;
import org.openid4java.association.Association;
import wsattacker.sso.openid.attacker.config.ToolConfiguration;
import wsattacker.sso.openid.attacker.config.XmlPersistenceError;
import wsattacker.sso.openid.attacker.config.XmlPersistenceHelper;
import wsattacker.sso.openid.attacker.controller.ServerController;
import wsattacker.sso.openid.attacker.server.buisinesslogic.CustomInMemoryServerAssociationStore;

/**
 * This class provides static methods for starting and stopping the main
 * programm
 */
final public class Bootstrap {

    final private static Logger LOG = Logger.getLogger(Bootstrap.class);
    final private static File DEFAULT_CONFIG_FILE = new File("openId_config.xml");
    final private static File DEFAULT_ASSOCIATION_FILE = new File("openId_associations.ser");
    private static boolean started = false;
    private static boolean stopped = false;
    private static ServerController controller = new ServerController();

    public static void onStart() {
        try {
            throwIfAlreadyStarted();
            readGlobalConfigFromDisk();
            readAssociationFromDisk();
        } catch (XmlPersistenceError ex) {
            LOG.warn("Error while starting the program");
        }
    }

    public static void onStop() {
        try {
            throwIfAlreadyStopped();
            saveGlobalConfigToDisk();
            saveAssociationToDisk();
        } catch (XmlPersistenceError ex) {
            LOG.warn("Error while stopping the program");
        }
    }

    private static void throwIfAlreadyStopped() {
        if (stopped) {
            throw new IllegalStateException("onStop() Method was already invoked");
        }
        stopped = true;
    }

    private static void throwIfAlreadyStarted() {
        if (started) {
            throw new IllegalStateException("onStart() Method was already invoked");
        }
        started = true;
    }

    private static void readGlobalConfigFromDisk() throws XmlPersistenceError {
        if (DEFAULT_CONFIG_FILE.isFile()) {         
            ToolConfiguration currentToolConfig = new ToolConfiguration();
            currentToolConfig.setAttackerConfig(controller.getAttackerConfig());
            currentToolConfig.setAnalyzerConfig(controller.getAnalyzerConfig());
            
            XmlPersistenceHelper.mergeConfigFileToConfigObject(DEFAULT_CONFIG_FILE, currentToolConfig);
        }
    }

    private static void saveGlobalConfigToDisk() throws XmlPersistenceError {
        controller.getConfig().setPerformAttack(false);
        
        ToolConfiguration currentToolConfig = new ToolConfiguration();
        currentToolConfig.setAttackerConfig(controller.getAttackerConfig());
        currentToolConfig.setAnalyzerConfig(controller.getAnalyzerConfig());
        
        XmlPersistenceHelper.saveConfigToFile(DEFAULT_CONFIG_FILE, currentToolConfig);
    }

    private static void readAssociationFromDisk() throws XmlPersistenceError {
        CustomInMemoryServerAssociationStore store = controller.getServer().getStore();
        List<Association> associationList = XmlPersistenceHelper.loadAssociationStoreFromFile(DEFAULT_ASSOCIATION_FILE);
        store.setAssociationList(associationList);
    }

    private static void saveAssociationToDisk() throws XmlPersistenceError {
        CustomInMemoryServerAssociationStore store = controller.getServer().getStore();
        List<Association> associationList = store.getAssociationList();
        XmlPersistenceHelper.saveAssociationStoreToDisk(DEFAULT_ASSOCIATION_FILE, associationList);
    }

    private Bootstrap() {
    }
}
