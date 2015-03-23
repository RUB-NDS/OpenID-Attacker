package wsattacker.sso.openid.attacker.attack;

import java.util.LinkedHashMap;
import java.util.Map;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import org.junit.Test;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameter;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameterHandler;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameterKeeper;
import wsattacker.sso.openid.attacker.attack.parameter.utilities.HttpMethod;

public class AttackParameterHandlerTest {

    public AttackParameterHandlerTest() {
    }

    @Test
    public void testUpdateValidParameters() {
        AttackParameterKeeper keeper = new AttackParameterKeeper();
        assertThat(keeper.keySet(), hasSize(0));

        Map<String, String> addMap = new LinkedHashMap<>();
        addMap.put("a", "one");
        addMap.put("b", "two");
        addMap.put("c", "three");
        AttackParameterHandler.updateValidParameters(keeper, addMap);
        assertThat(keeper.keySet(), hasSize(3));
        assertThat(keeper.getParameter("a").getValidValue(), is("one"));
        assertThat(keeper.getParameter("b").getValidValue(), is("two"));
        assertThat(keeper.getParameter("c").getValidValue(), is("three"));

        addMap.put("b", "TWO");
        addMap.put("d", "four");
        AttackParameterHandler.updateValidParameters(keeper, addMap);
        assertThat(keeper.keySet(), hasSize(4));
        assertThat(keeper.getParameter("a").getValidValue(), is("one"));
        assertThat(keeper.getParameter("b").getValidValue(), is("TWO"));
        assertThat(keeper.getParameter("c").getValidValue(), is("three"));
        assertThat(keeper.getParameter("d").getValidValue(), is("four"));

        keeper.clear();
        assertThat(keeper.keySet(), hasSize(0));
    }

    @Test
    public void testUpdateAttackParameters() {
        AttackParameterKeeper keeper = new AttackParameterKeeper();
        Map<String, String> addMap = new LinkedHashMap<>();
        addMap.put("a", "one");
        addMap.put("b", "two");
        addMap.put("c", "three");
        AttackParameterHandler.updateValidParameters(keeper, addMap);
        for (String name : keeper.keySet()) {
            keeper.getParameter(name).setAttackValueUsedForSignatureComputation(true);
        }

        Map<String, String> attackMap = new LinkedHashMap<>();
        attackMap.put("a", "atk_a");
        attackMap.put("b", "atk_b");
        attackMap.put("c", "atk_c");

        AttackParameterHandler.updateAttackParameters(keeper, attackMap);

        Map<String, String> expectedAttackMap = new LinkedHashMap<>();
        expectedAttackMap.put("a", "atk_a");
        expectedAttackMap.put("b", "atk_b");
        expectedAttackMap.put("c", "atk_c");


        Map<String, String> actualAttackMap = AttackParameterHandler.createToSignMap(keeper);
        assertThat(actualAttackMap, is(expectedAttackMap));

        attackMap.clear();
        attackMap.put("a", "new_atk_a");

        // parameter "a" should not be changed, because only automatic values are changed
        AttackParameterHandler.updateAttackParameters(keeper, attackMap);

        AttackParameter a = keeper.getParameter("a");
        assertThat(a.getAttackValue(), is("atk_a"));
        a.setAttackValueUsedForSignatureComputation(false);
        assertThat(a.getAttackValue(), is("new_atk_a"));
    }

    @Test
    public void testAddOrUpdateParameterValidValue() {
        AttackParameterKeeper keeper = new AttackParameterKeeper();
        keeper.addOrUpdateParameterValidValue("a", "one");
        assertThat(keeper.keySet(), hasSize(1));
        assertThat(keeper.getParameter("a").getValidValue(), is("one"));
        keeper.addOrUpdateParameterValidValue("a", "ONE");
        assertThat(keeper.keySet(), hasSize(1));
        assertThat(keeper.getParameter("a").getValidValue(), is("ONE"));
    }

    @Test
    public void testCreateMapByMethod() {
        AttackParameterKeeper keeper = new AttackParameterKeeper();

        AttackParameter a = keeper.addOrUpdateParameterValidValue("a", "one");
        a.setAttackValue("atk_one");
        a.setValidMethod(HttpMethod.GET);
        a.setAttackMethod(HttpMethod.POST);

        AttackParameter b = keeper.addOrUpdateParameterValidValue("b", "two");
        b.setAttackValue("atk_two");
        b.setValidMethod(HttpMethod.POST);
        b.setAttackMethod(HttpMethod.GET);

        AttackParameter c = keeper.addOrUpdateParameterValidValue("c", "three");
        c.setAttackValue("atk_three");
        c.setValidMethod(HttpMethod.DO_NOT_SEND);
        c.setAttackMethod(HttpMethod.DO_NOT_SEND);

        Map<String, String> expectedMap = new LinkedHashMap<>();
        expectedMap.put("a", "one");
        expectedMap.put("b", "atk_two");
        Map<String, String> getMap = AttackParameterHandler.createMapByMethod(keeper, HttpMethod.GET, true);
        assertThat(getMap, is(expectedMap));

        expectedMap.clear();
        expectedMap.put("a", "atk_one");
        expectedMap.put("b", "two");
        Map<String, String> postMap = AttackParameterHandler.createMapByMethod(keeper, HttpMethod.POST, true);
        assertThat(postMap, is(expectedMap));
    }
}
