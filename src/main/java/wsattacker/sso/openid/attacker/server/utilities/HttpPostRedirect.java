package wsattacker.sso.openid.attacker.server.utilities;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.lang3.StringEscapeUtils;
import org.openid4java.message.Message;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import wsattacker.sso.openid.attacker.config.OpenIdServerConfiguration;
import wsattacker.sso.openid.attacker.discovery.utilities.DomUtilities;

public class HttpPostRedirect {

    private static boolean value;

    public static String createPostRedirect(Message openidMessage) {
	    return createPostRedirect(openidMessage.getDestinationUrl(value), openidMessage.getParameterMap(), new HashMap<String, String>());
    }

    private static String createPostRedirect(final String destinationUrl, Map<String, String> getParameterMap, Map<String, String> postParameterMap) {
        boolean interceptIdPResonse = OpenIdServerConfiguration.getAttackerInstance().isInterceptIdPResponse();
        return createPostRedirect(destinationUrl, getParameterMap, postParameterMap, interceptIdPResonse);
    }

    public static String createPostRedirect(final String destinationUrl, Map<String, String> getParameterMap, Map<String, String> postParameterMap, boolean interceptIdPResonse) {
        String result = "";
        try {
            Document html = createBasicPostRedirect();
            Element title = findTitleElement(html);
            title.setTextContent(title.getTextContent() + destinationUrl);
            Element form = findFormElement(html);

            String getUrl = createGetRequest(destinationUrl, getParameterMap);
            form.setAttribute("action", getUrl);

            appendBasicInfos(form, destinationUrl, getUrl);
            appendGetParametersShowOnly(form, getParameterMap);
            appendPostParameters(form, postParameterMap);
            if (interceptIdPResonse) {
                findBodyElement(html).removeAttribute("onload");
            }
            result = DomUtilities.domToString(html, true);
        } catch (SAXException | IOException ex) {
            Logger.getLogger(HttpPostRedirect.class.getName()).log(Level.SEVERE, null, ex);
            throw new IllegalStateException("This should never happen", ex);
        }
        return result;
    }

    public static String createGetRequest(final String destinationUrl, final Map<String, String> getParameterMap) {
        StringBuilder sb = new StringBuilder();
        sb.append(destinationUrl);
        char join;
        if (destinationUrl.contains("?")) {
            join = '&';
        } else {
            join = '?';
        }
        for (Map.Entry<String, String> parameter : getParameterMap.entrySet()) {
            sb.append(join);
            sb.append(parameter.getKey());
            sb.append('=');
            String value;
            try {
                value = URLEncoder.encode(parameter.getValue(), "utf-8");
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(HttpPostRedirect.class.getName()).log(Level.SEVERE, null, ex);
                throw new IllegalStateException("This should never happen", ex);
            }
            sb.append(value);
            join = '&';
        }
        return sb.toString();
    }

    static void appendBasicInfos(Element form, final String destinationUrl, final String getUrl) {
        Document doc = form.getOwnerDocument();

        Element fieldset = doc.createElement("fieldset");
        form.appendChild(fieldset);

        Element legend = doc.createElement("legend");
        legend.setTextContent("Basic Information:");
        fieldset.appendChild(legend);

        Element table = doc.createElement("table");
        fieldset.appendChild(table);
        appendBasicInfo(table, "Basic URL", destinationUrl);
        appendBasicInfo(table, "Action URL", getUrl);
    }

    static void appendBasicInfo(Element table, String name, String value) {
        Document doc = table.getOwnerDocument();
        Element tr = doc.createElement("tr");
        table.appendChild(tr);

        Element tdLeft = doc.createElement("td");
        tr.appendChild(tdLeft);
        tdLeft.setTextContent(name);

        Element tdRight = doc.createElement("td");
        tr.appendChild(tdRight);

        Element a = doc.createElement("a");
        tdRight.appendChild(a);
        a.setAttribute("href", value);
        a.setTextContent(StringEscapeUtils.escapeHtml4(value));
    }

    static void appendGetParametersShowOnly(Element form, final Map<String, String> getParameterMap) {
        Document doc = form.getOwnerDocument();

        Element fieldset = doc.createElement("fieldset");
        form.appendChild(fieldset);

        Element legend = doc.createElement("legend");
        legend.setTextContent("GET Parameters:");
        fieldset.appendChild(legend);

        Element table = doc.createElement("table");

        for (Map.Entry<String, String> parameter : getParameterMap.entrySet()) {
            Element tr = doc.createElement("tr");
            table.appendChild(tr);

            Element tdLeft = doc.createElement("td");
            tr.appendChild(tdLeft);
            tdLeft.setTextContent(parameter.getKey());

            Element tdRight = doc.createElement("td");
            tr.appendChild(tdRight);
            String value = StringEscapeUtils.escapeHtml4(parameter.getValue());
            tdRight.setTextContent(value);
        }
        if (!getParameterMap.isEmpty()) {
            fieldset.appendChild(table);
        }
    }

    static void appendPostParameters(Element form, final Map<String, String> postParameterMap) {
        Document doc = form.getOwnerDocument();

        Element fieldset = doc.createElement("fieldset");
        form.appendChild(fieldset);

        Element legend = doc.createElement("legend");
        legend.setTextContent("POST Parameters:");
        fieldset.appendChild(legend);

        Element table = doc.createElement("table");
        fieldset.appendChild(table);

        for (Map.Entry<String, String> parameter : postParameterMap.entrySet()) {
            Element tr = doc.createElement("tr");
            table.appendChild(tr);

            Element tdLeft = doc.createElement("td");
            tr.appendChild(tdLeft);
            tdLeft.setTextContent(parameter.getKey());

            Element tdRight = doc.createElement("td");
            tr.appendChild(tdRight);

            // <input type="hidden" name="SAMLResponse" value=""/>
            Element input = doc.createElement("input");
            input.setAttribute("size", "120");
            input.setAttribute("type", "text");
            input.setAttribute("name", parameter.getKey());
            input.setAttribute("value", parameter.getValue());
            tdRight.appendChild(input);
        }
    }

    static Element findBodyElement(final Document html) {
        Element root = html.getDocumentElement();
        return (Element) root.getElementsByTagName("body").item(0);
    }

    static Element findFormElement(final Document html) {
        Element body = findBodyElement(html);
        return (Element) body.getElementsByTagName("form").item(0);
    }

    static Element findTitleElement(final Document html) {
        Element root = html.getDocumentElement();
        Element body = (Element) root.getElementsByTagName("head").item(0);
        return (Element) body.getElementsByTagName("title").item(0);
    }

    static Document createBasicPostRedirect() throws SAXException, IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder;
        try {
            builder = factory.newDocumentBuilder();
            InputStream is = HttpPostRedirect.class.getResourceAsStream("/post-redirect.html");
            return builder.parse(is);
        } catch (ParserConfigurationException ex) {
            Logger.getLogger(HttpPostRedirect.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private HttpPostRedirect() {
    }
}
