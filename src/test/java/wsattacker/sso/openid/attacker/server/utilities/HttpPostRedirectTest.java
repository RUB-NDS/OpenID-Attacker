package wsattacker.sso.openid.attacker.server.utilities;

import java.util.HashMap;
import java.util.Map;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class HttpPostRedirectTest {

    public HttpPostRedirectTest() {
    }

    @Test
    public void testCreateBasicPostRedirect() throws Exception {
        Document doc = HttpPostRedirect.createBasicPostRedirect();
        assertThat(doc.getDocumentElement().getLocalName(), is("html"));

        Element form = HttpPostRedirect.findFormElement(doc);
        assertThat(form.getLocalName(), is("form"));

        Element title = HttpPostRedirect.findTitleElement(doc);
        assertThat(title.getLocalName(), is("title"));
    }

    @Test
    public void testCreateGetRequest() {
        String url = "http://x.yz";
        Map<String, String> getMap = new HashMap<>();
        getMap.put("eins", "one");
        getMap.put("zwei", "two");

        String expected = url + "?zwei=two&eins=one";
        String actual = HttpPostRedirect.createGetRequest(url, getMap);
        assertThat(actual, is(expected));
    }

    @Test
    public void testCreateGetRequest2() {
        String url = "http://x.yz?q=s";
        Map<String, String> getMap = new HashMap<>();
        getMap.put("eins", "one");
        getMap.put("zwei", "two");

        String expected = url + "&zwei=two&eins=one";
        String actual = HttpPostRedirect.createGetRequest(url, getMap);
        assertThat(actual, is(expected));
    }

    @Test
    public void testCreateGetRequest3() {
        String url = "http://x.yz";
        Map<String, String> getMap = new HashMap<>();
        getMap.put("a", "x y");

        String expected = url + "?a=x+y";
        String actual = HttpPostRedirect.createGetRequest(url, getMap);
        assertThat(actual, is(expected));
    }

    @Test
    public void testCreateGetRequest4() {
        String url = "http://x.yz";
        Map<String, String> getMap = new HashMap<>();
        getMap.put("a", "x+y");

        String expected = url + "?a=x%2By";
        String actual = HttpPostRedirect.createGetRequest(url, getMap);
        assertThat(actual, is(expected));
    }
}
