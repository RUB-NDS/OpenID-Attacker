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
package wsattacker.sso.openid.attacker.discovery.xrds;

import javax.xml.XMLConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.sso.openid.attacker.discovery.utilities.DomUtilities;

final public class XrdsGenerator {

    private static final String XMLNS = "xri://$xrd*($v*2.0)";
    private static final String XMLNS_XRDS = "xri://$xrds";
    private static final String XMLNS_OPENID = "http://openid.net/xmlns/1.0";

    private XrdsGenerator() {
    }

    public static Document generateXrdsDocument(XrdsConfiguration config) {
        Element xrd = createEmptyXRDElement();
        Document xrdsDocument = xrd.getOwnerDocument();
        Element service = createService(xrdsDocument, config);
        xrd.appendChild(service);
        return xrdsDocument;
    }

    public static String generateString(XrdsConfiguration config) {
        Document xrdsDocument = generateXrdsDocument(config);
        return DomUtilities.domToString(xrdsDocument, true);
    }

    private static Element createService(Document xrdsDoc, XrdsConfiguration config) {
        // Create
        // <Service priority="$priority">
        final Element serviceElement = xrdsDoc.createElement("Service");
        serviceElement.setAttribute("priority", String.valueOf(config.getPriority()));

        // Create
        // <Type>http://specs.openid.net/auth/2.0/signon</Type>
        final Element typeElement = xrdsDoc.createElement("Type");
        serviceElement.appendChild(typeElement);
        final OpenIdVersion version = config.getOpenIdVersion();
        typeElement.setTextContent(version.getURI());

        // Create
        // <URI>$endpoint</URI>
        final Element endpointElement = xrdsDoc.createElement("URI");
        serviceElement.appendChild(endpointElement);
        endpointElement.setTextContent(config.getBaseUrl());

        // Create
        // <LocalID>$openid_identifier</LocalID>
        // or
        // <openid:Delegate>$openid_identifier</openid:Delegate>
        if (config.isIncludeIdentity()) {
            final Element identifierElement;
            if (version == OpenIdVersion.VERSION_20_CLAIMED_IDENTIFIER_ELEMENT || version == OpenIdVersion.VERSION_20_OP_IDENTIFIER_ELEMENT) {
                String identfierElementName = "LocalID";
                identifierElement = xrdsDoc.createElement(identfierElementName);
            } else {
                String identfierElementName = "openid:Delegate";
                identifierElement = xrdsDoc.createElementNS(XMLNS_OPENID, identfierElementName);
            }
            serviceElement.appendChild(identifierElement);
            identifierElement.setTextContent(config.getIdentity());
        }

        // Return <Service/> Element
        return serviceElement;
    }

    private static Element createEmptyXRDElement() {
        Document xrdsDoc = DomUtilities.createEmptyDom();
//        Element root = xrdsDoc.createElement("xrds:XRDS");
        Element root = xrdsDoc.createElementNS(XMLNS_XRDS, "xrds:XRDS");
        xrdsDoc.appendChild(root);
        root.setAttribute("xmlns", XMLNS);
//        root.setAttribute("xmlns:xrds", XMLNS_XRDS);
//        root.setAttribute("xmlns:openid", XMLNS_OPENID);
        root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:xrds", XMLNS_XRDS);
        root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:openid", XMLNS_OPENID);

        Element xrd = xrdsDoc.createElement("XRD");
        root.appendChild(xrd);
        xrd.setAttribute("version", "2.0");
        return xrd;
    }
}
