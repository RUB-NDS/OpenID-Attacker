package wsattacker.sso.openid.attacker.discovery.html;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.dom.DOMSource;
import static org.junit.Assert.assertThat;
import org.junit.Ignore;
import org.junit.Test;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import static org.xmlmatchers.XmlMatchers.isEquivalentTo;

public class HtmlDiscoveryGeneratorTest {

    private static final String BASE_URL = "http://openidp";
    private static final String IDENTITY = "http://openidp/identity";

    public HtmlDiscoveryGeneratorTest() {
    }

    @Test
    @Ignore
    public void testGenerateString() throws Exception {
        HtmlDiscoveryConfiguration config = createConfig(true, true, false);
        Document result = HtmlDiscoveryGenerator.generateHtmlDocument(config);
        Document expected = string2Document(
          "<html>\n"
          + "   <head>\n"
          + "      <title>http://openidp/identity</title>\n"
          + "      <link href=\"http://openidp\" rel=\"openid.server\" />\n"
          + "      <link href=\"http://openidp\" rel=\"openid2.provider\" />\n"
          + "   </head>\n"
          + "   <body>\n"
          + "      <p>HTML Discovery for:</p>\n"
          + "      <p>http://openidp/identity</p>\n"
          + "   </body>\n"
          + "</html>");
        assertThat(new DOMSource(result), isEquivalentTo(new DOMSource(expected)));
    }

    private HtmlDiscoveryConfiguration createConfig(final boolean openidserver, final boolean openid2provider, final boolean includeIdentity) {
        HtmlDiscoveryConfiguration config = new HtmlDiscoveryConfiguration();
        config.setBaseUrl(BASE_URL);
        config.setIdentity(IDENTITY);
        config.setIncludeIdentity(includeIdentity);
        config.setOpenidServer(openidserver);
        config.setOpenId2Provider(openid2provider);
        return config;
    }

    private static Document string2Document(String xml) throws SAXException, IOException {
        DocumentBuilderFactory fac = DocumentBuilderFactory.newInstance();
        fac.setNamespaceAware(false);
        // fac.setIgnoringElementContentWhitespace(true);
        DocumentBuilder builder = null;
        try {
            builder = fac.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException("This should never happen", e);
        }
        InputStream is = new ByteArrayInputStream(xml.getBytes("UTF-8"));
        return builder.parse(is);
    }
}
