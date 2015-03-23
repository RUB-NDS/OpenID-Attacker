package wsattacker.sso.openid.attacker.server.buisinesslogic;

import junit.framework.TestCase;
import static org.apache.commons.lang.RandomStringUtils.randomAscii;
import static org.apache.commons.lang.RandomStringUtils.randomNumeric;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openid4java.message.Message;
import org.openid4java.message.Parameter;
import org.openid4java.message.ParameterList;
import org.openid4java.server.ServerManager;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameterKeeper;
import wsattacker.sso.openid.attacker.config.OpenIdServerConfiguration;

public class CustomOpenIdProcessorTest extends TestCase {

    private CustomOpenIdProcessor processor;
    private CustomInMemoryServerAssociationStore store;
    private ServerManager manager;

    public CustomOpenIdProcessorTest(String testName) {
        super(testName);
    }

    @BeforeClass
    public void setUpClass() {
        // Just for the case of debugging...
        OpenIdServerConfiguration.getInstance().setAssociationExpirationInSeconds(3600);
    }

    @Before
    @Override
    public void setUp() {
        processor = new CustomOpenIdProcessor();
        store = new CustomInMemoryServerAssociationStore();
        processor.setStore(store);
        processor.setEndpoint("http://localhost");
        manager = processor.getServerManager();
    }

    @Test
    public void testOpenidAssociate() throws Exception {
        final String ASSOC_QUERY = "openid.dh_consumer_public=MTEK&openid.mode=associate&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.session_type=DH-SHA1&openid.assoc_type=HMAC-SHA1";
        final String PARAM_ASSOC = "assoc_handle";
        String EXPECTED_ASSOC_VALUE = randomAscii(20);
        ParameterList assoc_parameter = ParameterList.createFromQueryString(ASSOC_QUERY);

        Message response = manager.associationResponse(assoc_parameter);
        String assoc_value = response.getParameterValue(PARAM_ASSOC);
        assertThat(assoc_value, not(equalTo(EXPECTED_ASSOC_VALUE)));

        CustomInMemoryServerAssociationStore store = new CustomInMemoryServerAssociationStore();
        store.setAssociationPrefix(EXPECTED_ASSOC_VALUE);
        manager.setSharedAssociations(store);

        response = processor.processAssociationRequest(assoc_parameter);
        assoc_value = response.getParameterValue(PARAM_ASSOC);
        assertThat(assoc_value, equalTo(EXPECTED_ASSOC_VALUE));

        // what happens if we ask multiple times with same assoc prefix?
        for (int i = 1; i < 5; ++i) {
            response = processor.processAssociationRequest(assoc_parameter);
            assoc_value = response.getParameterValue(PARAM_ASSOC);
            assertThat(assoc_value, equalTo(EXPECTED_ASSOC_VALUE + "-" + i));
        }

        // Now reset the assoc prefix
        EXPECTED_ASSOC_VALUE = randomNumeric(20);
        store.setAssociationPrefix(EXPECTED_ASSOC_VALUE);
        response = processor.processAssociationRequest(assoc_parameter);
        assoc_value = response.getParameterValue(PARAM_ASSOC);
        assertThat(assoc_value, equalTo(EXPECTED_ASSOC_VALUE));
    }

    @Test
    public void testOpenidGenerateResponse() throws Exception {
        final String EXPECTED_ASSOC_VALUE = "MY_CUSTOM_ASSOC_VALUE";

        ParameterList assoc_parameter = new ParameterList();
        assoc_parameter.set(new Parameter("openid.dh_consumer_public", "MTEK"));
        assoc_parameter.set(new Parameter("openid.mode", "associate"));
        assoc_parameter.set(new Parameter("openid.ns", "http://specs.openid.net/auth/2.0"));
        assoc_parameter.set(new Parameter("openid.session_type", "DH-SHA1"));
        assoc_parameter.set(new Parameter("openid.assoc_type", "HMAC-SHA1"));

//        System.out.println("### REQUEST:\n" + assoc_parameter.toString());
        store.setAssociationPrefix(EXPECTED_ASSOC_VALUE);

        Message responseAuthenticaton = processor.processAssociationRequest(assoc_parameter);
        String assoc_value = responseAuthenticaton.getParameterValue("assoc_handle");
        assertThat(assoc_value, equalTo(EXPECTED_ASSOC_VALUE));

        ParameterList generate_parameter = new ParameterList();
        generate_parameter.set(new Parameter("openid.ns", "http://specs.openid.net/auth/2.0"));
//        generate_parameter.set(new Parameter("openid.realm", "http://realm"));
        generate_parameter.set(new Parameter("openid.mode", "checkid_setup"));
        generate_parameter.set(new Parameter("openid.return_to", "http://return"));
        generate_parameter.set(new Parameter("openid.claimed_id", "http://claimed"));
        generate_parameter.set(new Parameter("openid.identity", "http://identity"));
        generate_parameter.set(new Parameter("openid.assoc_handle", assoc_value));

//        System.out.println("### GENERATE:\n" + generate_parameter);
        AttackParameterKeeper responseToken = processor.processTokenRequest(generate_parameter);
//        responseToken.validate();
//        System.out.println("### TOKEN:\n" + responseToken.toString());

        // is there a signature?
        assertThat(responseToken.getParameter("openid.sig") != null, is(true));

    }
    //        final String RESPONSE_QUERY = "openid=consumer&janrain_nonce=2013-07-01T16%3A16%3A38ZlIosLe&openid.mode=id_res&openid.op_endpoint=http%3A%2F%2Fxml.nds.rub.de%3A8080%2Fsimpleid%2Fwww%2F&openid.response_nonce=2013-07-01T16%3A16%3A44Zf3c7ef36&openid.assoc_handle=51d1ab660008ab36c99b8e59&openid.identity=http%3A%2F%2Flocalhost%2Fsimpleid%2Fwww%2Findex.php%3Fq%3Dxrds%2Fitsme&openid.return_to=http%3A%2F%2Flocalhost%2Fwordpress%2F%3Fopenid%3Dconsumer%26janrain_nonce%3D2013-07-01T16%253A16%253A38ZlIosLe&openid.claimed_id=http%3A%2F%2Flocalhost%2Fsimpleid%2Fwww%2Findex.php%3Fq%3Dxrds%2Fitsme&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.signed=response_nonce%2Creturn_to%2Cassoc_handle%2Cop_endpoint%2Cidentity%2Cclaimed_id&openid.sig=I0UBOJpUz%2BtAh5%2FOzzbzQvAHnrw%3D";
//
//        ParameterList response_parameter = ParameterList.createFromQueryString(RESPONSE_QUERY);
//
//        System.out.println("### RESPONSE:\n" + response_parameter);
}
