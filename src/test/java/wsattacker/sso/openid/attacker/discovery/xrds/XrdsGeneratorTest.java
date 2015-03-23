package wsattacker.sso.openid.attacker.discovery.xrds;

import java.io.IOException;
import java.io.InputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.dom.DOMSource;
import static org.junit.Assert.assertThat;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import static org.xmlmatchers.XmlMatchers.isEquivalentTo;
import static wsattacker.sso.openid.attacker.discovery.xrds.XrdsGenerator.generateXrdsDocument;
import wsattacker.sso.openid.attacker.user.User;

public class XrdsGeneratorTest {

    public static final String CLAIMED_ID = "http://my_claimed_id";
    private static XrdsConfiguration config;
    private static final User user = new User();
    private static final String ENDPOINT = "http://my_endpoint";

    @BeforeClass
    public static void setUpBeforeClass() {
        config = new XrdsConfiguration();
        config.setIdentity(CLAIMED_ID);
        config.setBaseUrl(ENDPOINT);
        config.setIncludeIdentity(true);
    }

    public static Document readDocument(InputStream is) throws SAXException, IOException {
        DocumentBuilderFactory fac = DocumentBuilderFactory.newInstance();
        fac.setNamespaceAware(false);
        // fac.setIgnoringElementContentWhitespace(true);
        DocumentBuilder builder = null;
        try {
            builder = fac.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException("This should never happen", e);
        }
        return builder.parse(is);
    }

    public XrdsGeneratorTest() {
    }

    @Before
    public void setUp() {
    }

    @Test
    public void testGenerateXrdsDocument20() throws Exception {
        Document expected = readDocument(XrdsGeneratorTest.class.getResourceAsStream("/xrds/xrds_20.xml"));
        config.setOpenIdVersion(OpenIdVersion.VERSION_20_CLAIMED_IDENTIFIER_ELEMENT);
        Document xrdsDocument = generateXrdsDocument(config);
        assertThat(new DOMSource(expected), isEquivalentTo(new DOMSource(xrdsDocument)));
    }

    @Test
    public void testGenerateXrdsDocument11() throws Exception {
        Document expected = readDocument(XrdsGeneratorTest.class.getResourceAsStream("/xrds/xrds_11.xml"));
        config.setOpenIdVersion(OpenIdVersion.VERSION_11);
        Document xrdsDocument = generateXrdsDocument(config);
        assertThat(new DOMSource(expected), isEquivalentTo(new DOMSource(xrdsDocument)));
    }

    @Test
    public void testGenerateXrdsDocument10() throws Exception {
        Document expected = readDocument(XrdsGeneratorTest.class.getResourceAsStream("/xrds/xrds_10.xml"));
        config.setOpenIdVersion(OpenIdVersion.VERSION_10);
        Document xrdsDocument = generateXrdsDocument(config);
        assertThat(new DOMSource(expected), isEquivalentTo(new DOMSource(xrdsDocument)));
    }
}
