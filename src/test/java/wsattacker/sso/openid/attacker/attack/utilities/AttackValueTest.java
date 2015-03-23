package wsattacker.sso.openid.attacker.attack.utilities;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;
import org.junit.Test;
import wsattacker.sso.openid.attacker.attack.parameter.utilities.AttackValue;

public class AttackValueTest {

    public static final String USER_VALUE_1 = "userValue_1";
    public static final String AUTOMATIC_VALUE_1 = "automaticValue_1";
    public static final String USER_VALUE_2 = "userValue_2";
    public static final String AUTOMATIC_VALUE_2 = "automaticValue_2";

    public AttackValueTest() {
    }

    @Test
    public void testNotNullValue() {
        AttackValue av = new AttackValue();

        assertThat(av.getUserValue(), notNullValue());
        assertThat(av.getAutomaticValue(), notNullValue());
        assertThat(av.getCurrentValue(), notNullValue());
    }

    @Test
    public void testDefaultAttackNotEnabled() {
        AttackValue av = new AttackValue();

        assertThat(av.isEnableUserValue(), is(false));
    }

    @Test
    public void testGetCurrentValue() {
        AttackValue av = new AttackValue();

        av.setUserValue(USER_VALUE_1);
        av.setAutomaticValue(AUTOMATIC_VALUE_1);

        assertThat(av.getAutomaticValue(), is(AUTOMATIC_VALUE_1));
        assertThat(av.getUserValue(), is(USER_VALUE_1));

        av.setEnableUserValue(false);
        assertThat(av.getCurrentValue(), is(AUTOMATIC_VALUE_1));
        av.setCurrentValue(AUTOMATIC_VALUE_2);
        assertThat(av.getCurrentValue(), is(AUTOMATIC_VALUE_2));
        assertThat(av.getAutomaticValue(), is(AUTOMATIC_VALUE_2));

        av.setEnableUserValue(true);
        assertThat(av.getCurrentValue(), is(USER_VALUE_1));
        av.setCurrentValue(USER_VALUE_2);
        assertThat(av.getCurrentValue(), is(USER_VALUE_2));
        assertThat(av.getUserValue(), is(USER_VALUE_2));
    }
}
