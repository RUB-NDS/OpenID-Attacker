package wsattacker.sso.openid.attacker.attack.parameter;

import java.util.List;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import org.junit.Test;
import wsattacker.sso.openid.attacker.attack.parameter.utilities.SearchReplaceHolder;

public class SearchReplaceAttackParameterTest {

    public SearchReplaceAttackParameterTest() {
    }

    @Test
    public void testSingleReplace() {
        final SearchReplaceHolder srh = new SearchReplaceHolder("two", "ZWEI", false);
        searchReplaceTest("one_two_three_four_five", "one_ZWEI_three_four_five", srh);
    }

    @Test
    public void testDoubleReplace() {
        final SearchReplaceHolder srh1 = new SearchReplaceHolder("two", "ZWEI", false);
        final SearchReplaceHolder srh2 = new SearchReplaceHolder("five", "FUENF", false);
        searchReplaceTest("one_two_three_four_five", "one_ZWEI_three_four_FUENF", srh2, srh1);
    }

    @Test
    public void testWithEncoding() {
        final String search = "http://idp1.nds.rub.de:8080/simpleid/www/";
        final String replace = "https://idp2.nds.rub.de:9090/elsewhere/";
        final SearchReplaceHolder srh = new SearchReplaceHolder(search, replace, true);
        String returnUrl = "https://www.sp.org/login?openid1_claimed_id=http%3A%2F%2Fidp1.nds.rub.de%3A8080%2Fsimpleid%2Fwww%2F&rp_nonce=2013-10-02T14%3A56%3A59Zc5gyX5";
        String expectedUrl = "https://www.sp.org/login?openid1_claimed_id=https%3A%2F%2Fidp2.nds.rub.de%3A9090%2Felsewhere%2F&rp_nonce=2013-10-02T14%3A56%3A59Zc5gyX5";
        searchReplaceTest(returnUrl, expectedUrl, srh);
    }

    public void searchReplaceTest(String initialString, String expectedResult, SearchReplaceHolder... searchReplace) {
        final SearchReplaceAttackParameter parameter = new SearchReplaceAttackParameter();
        parameter.setName("openid.return_to");
        parameter.setValidValue(initialString);

        final List<SearchReplaceHolder> searchReplaceList = parameter.getSearchReplaceList();
        for (SearchReplaceHolder srh : searchReplace) {
            searchReplaceList.add(srh);
        }

        String result = parameter.getAttackValue();

        assertThat(result, is(expectedResult));

    }
}
