package wsattacker.sso.openid.attacker.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import org.apache.commons.beanutils.BeanUtils;
import org.apache.log4j.Logger;
import org.openid4java.association.Association;

/**
 * This helper utility class is able to save and to load the current config
 * to/from an XML file.
 */
final public class XmlPersistenceHelper {

    private static final Logger LOG = Logger.getLogger(XmlPersistenceHelper.class);

    private XmlPersistenceHelper() {
    }

    /**
     * Saves the current config to an XML file.
     *
     * @param saveFile
     */
    public static void saveConfigToFile(File saveFile, final ToolConfiguration toolConfigToSave) throws XmlPersistenceError {
        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(ToolConfiguration.class);
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            jaxbMarshaller.marshal(toolConfigToSave, saveFile);
            LOG.info(String.format("Saved successfully config to '%s'", saveFile.getAbsoluteFile()));
        } catch (JAXBException ex) {
            throw new XmlPersistenceError(String.format("Could not save config to File '%s'", saveFile.getAbsoluteFile()), ex);
        }
    }

    /**
     * Load the current config from an XML file.
     *
     * @param loadFile
     */
    public static void mergeConfigFileToConfigObject(final File loadFile, ToolConfiguration currentToolConfig) throws XmlPersistenceError {
        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(ToolConfiguration.class);
            Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
            ToolConfiguration loadedConfig = (ToolConfiguration) jaxbUnmarshaller.unmarshal(loadFile);
            
            //BeanUtils.copyProperties(currentToolConfig, loadedConfig);
            //ServerController controller = new ServerController();
            BeanUtils.copyProperties(currentToolConfig.getAttackerConfig(), loadedConfig.getAttackerConfig());
            BeanUtils.copyProperties(currentToolConfig.getAnalyzerConfig(), loadedConfig.getAnalyzerConfig());
            
            LOG.info(String.format("Loaded successfully config from '%s'", loadFile.getAbsoluteFile()));
        } catch (InvocationTargetException | IllegalAccessException | JAXBException ex) {
            throw new XmlPersistenceError(String.format("Could not load config from File '%s'", loadFile.getAbsoluteFile()), ex);
        }
    }

    public static void saveAssociationStoreToDisk(File saveFile, List<Association> associationList) throws XmlPersistenceError {
//        try {
//            JAXBContext jaxbContext = JAXBContext.newInstance(CustomInMemoryServerAssociationStore.class);
//            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
//            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
//            jaxbMarshaller.marshal(associationStore, saveFile);
//            LOG.info(String.format("Saved successfully associations to '%s'", saveFile.getAbsoluteFile()));
//        } catch (JAXBException ex) {
//            throw new XmlPersistenceError(String.format("Could not save associations to File '%s'", saveFile.getAbsoluteFile()), ex);
//        }
        try {
            FileOutputStream f_out = new FileOutputStream(saveFile);
            ObjectOutputStream obj_out = new ObjectOutputStream(f_out);
            obj_out.writeObject(associationList);
        } catch (IOException ex) {
            throw new XmlPersistenceError(String.format("Could not save associations to File '%s'", saveFile.getAbsoluteFile()), ex);
        }
    }

    public static List<Association> loadAssociationStoreFromFile(final File loadFile) throws XmlPersistenceError {
//        CustomInMemoryServerAssociationStore result;
//        try {
//            JAXBContext jaxbContext = JAXBContext.newInstance(CustomInMemoryServerAssociationStore.class);
//            Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
//            result = (CustomInMemoryServerAssociationStore) jaxbUnmarshaller.unmarshal(loadFile);
//            LOG.info(String.format("Loaded successfully associations from '%s'", loadFile.getAbsoluteFile()));
//        } catch (JAXBException ex) {
//            throw new XmlPersistenceError(String.format("Could not load associations from File '%s'", loadFile.getAbsoluteFile()), ex);
//        }
//        return result;
        // Read from disk using FileInputStream
        try {
            FileInputStream f_in;
            f_in = new FileInputStream(loadFile);
            ObjectInputStream obj_in = new ObjectInputStream(f_in);
            Object obj = obj_in.readObject();
            return (List<Association>) obj;
        } catch (IOException | ClassNotFoundException ex) {
            throw new XmlPersistenceError(String.format("Could not load associations from File '%s'", loadFile.getAbsoluteFile()), ex);
        }
    }
}
