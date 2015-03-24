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
package wsattacker.sso.openid.attacker.discovery.html;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import wsattacker.sso.openid.attacker.discovery.utilities.DomUtilities;

final public class HtmlDiscoveryGenerator {

    final static String NEWLINE = System.getProperty("line.separator");

    public static String generateString(HtmlDiscoveryConfiguration config) {
//        Document htmlDocument = generateHtmlDocument(config);
//        return DomUtilities.domToString(htmlDocument, true);
        final String baseUrl = config.getBaseUrl();
        final String idenentity = config.getIdentity();
        StringBuilder sb = new StringBuilder();
        sb.append("<html>").append(NEWLINE);
        sb.append("    <head>").append(NEWLINE);
        sb.append("    <title>");
        sb.append(idenentity);
        sb.append("</title>").append(NEWLINE);
        if (config.isOpenidServer()) {
            sb.append("    <link rel=\"openid.server\" href=\"");
            sb.append(baseUrl);
            sb.append("\" />").append(NEWLINE);
            if (config.isIncludeIdentity()) {
                sb.append("    <link rel=\"openid.delegate\" href=\"");
                sb.append(idenentity);
                sb.append("\" />").append(NEWLINE);
            }
        }
        if (config.isOpenId2Provider()) {
            sb.append("    <link rel=\"openid2.provider\" href=\"");
            sb.append(baseUrl);
            sb.append("\" />").append(NEWLINE);
            if (config.isIncludeIdentity()) {
                sb.append("    <link rel=\"openid2.local_id\" href=\"");
                sb.append(idenentity);
                sb.append("\" />").append(NEWLINE);
            }
        }
        sb.append("    </head>").append(NEWLINE);
        sb.append("    <body>").append(NEWLINE);
        sb.append("        <p>HTML Discovery for:</p>").append(NEWLINE);
        sb.append("        <p>");
        sb.append(idenentity);
        sb.append("</p>").append(NEWLINE);
        sb.append("    </body>").append(NEWLINE);
        sb.append("</html>").append(NEWLINE);
        return sb.toString();
    }

    protected static Document generateHtmlDocument(HtmlDiscoveryConfiguration config) {
        Document htmlDoc = DomUtilities.createEmptyDom();
        Element html = appendElement(htmlDoc, htmlDoc, "html");
        generateHtmlHead(html, config);
        generateHtmlBody(html, config);
        return htmlDoc;
    }

    private static Element appendElement(Node parentElement, final String childName) {
        final Document ownerDocument = parentElement.getOwnerDocument();
        return appendElement(ownerDocument, parentElement, childName);
    }

    private static void generateHtmlBody(Element html, final HtmlDiscoveryConfiguration config) {
        final String identity = config.getIdentity();
        Element body = appendElement(html, "body");
        Element p1 = appendElement(body, "p");
        p1.setTextContent("HTML Discovery for:");
        Element p2 = appendElement(body, "p");
        p2.setTextContent(identity);
    }

    private static void generateHtmlHead(Element html, final HtmlDiscoveryConfiguration config) {
        final String identity = config.getIdentity();
        Element head = appendElement(html, "head");
        Element title = appendElement(head, "title");
        title.setTextContent(identity);
        addOpenIdServerIfWanted(config, head);
        addOpenId2ProviderIfWanted(config, head);
        addOpenIdLocalIdentityIfWanted(config, head);
    }

    private static void addOpenIdLink(Element parent, final String name, final String value) {
        Element link = appendElement(parent, "link");
        link.setAttribute("rel", name);
        link.setAttribute("href", value);
    }

    private static void addOpenIdServerIfWanted(final HtmlDiscoveryConfiguration config, Element head) {
        if (config.isOpenidServer()) {
            final String name = "openid.server";
            final String value = config.getBaseUrl();
            addOpenIdLink(head, name, value);
        }
    }

    private static void addOpenId2ProviderIfWanted(final HtmlDiscoveryConfiguration config, Element head) {
        if (config.isOpenId2Provider()) {
            final String name = "openid2.provider";
            final String value = config.getBaseUrl();
            addOpenIdLink(head, name, value);
        }
    }

    private static void addOpenIdLocalIdentityIfWanted(final HtmlDiscoveryConfiguration config, Element head) {
        if (config.isIncludeIdentity()) {
            final String name = "openid2.local_id";
            final String value = config.getIdentity();
            addOpenIdLink(head, name, value);
        }
    }

    private static Element appendElement(final Document ownerDocument, Node parentElement, final String childName) {
        final Element childElement = ownerDocument.createElement(childName);
        parentElement.appendChild(childElement);
        return childElement;
    }

    private HtmlDiscoveryGenerator() {
    }
}
