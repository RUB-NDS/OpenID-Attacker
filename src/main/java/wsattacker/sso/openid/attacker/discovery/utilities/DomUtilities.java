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
package wsattacker.sso.openid.attacker.discovery.utilities;

import java.io.StringWriter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import wsattacker.sso.openid.attacker.discovery.xrds.XrdsConfiguration;

final public class DomUtilities {

    public static Document createEmptyDom() {
        Document doc = null;
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            doc = builder.newDocument();
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException("This should never happen", e);
        }
        return doc;
    }

    public static String domToString(Node n, boolean prettyPrint) {
        StringWriter output = new StringWriter();
        Transformer transformer;
        try {
            transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            if (prettyPrint) {
                transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
                transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            }
            transformer.transform(new DOMSource(n), new StreamResult(output));
	} catch (IllegalArgumentException | TransformerException e) {
            throw new IllegalStateException(String.format("%s.domToString() throws an Exception. This should never happen", XrdsConfiguration.class.getName()), e);
        }
        return output.toString();
    }

    /**
     * Converts a DOM Node to a String
     *
     * @param Node
     *             n
     *
     * @return
     */
    public static String domToString(Node n) {
        return domToString(n, false);
    }

    private DomUtilities() {
    }
}
