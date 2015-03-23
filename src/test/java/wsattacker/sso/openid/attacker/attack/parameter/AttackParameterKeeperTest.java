package wsattacker.sso.openid.attacker.attack.parameter;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThat;
import org.junit.Test;

public class AttackParameterKeeperTest {

    public AttackParameterKeeperTest() {
    }

    @Test
    public void testValidSignedCorrectByAdding() {
        AttackParameterKeeper keeper = new AttackParameterKeeper();
        AttackParameter a = keeper.addOrUpdateParameterValidValue("openid.a", "one");
        AttackParameter b = keeper.addOrUpdateParameterValidValue("openid.b", "two");

        assertThat(a.isInValidSignature(), is(false));
        assertThat(b.isInValidSignature(), is(false));


        keeper.addOrUpdateParameterValidValue("openid.signed", "a");

        assertThat(a.isInValidSignature(), is(true));
        assertThat(b.isInValidSignature(), is(false));
    }

    @Test
    public void testValidSignedCorrectByModification() {
        AttackParameterKeeper keeper = new AttackParameterKeeper();
        AttackParameter a = keeper.addOrUpdateParameterValidValue("openid.a", "one");
        AttackParameter b = keeper.addOrUpdateParameterValidValue("openid.b", "two");

        assertThat(a.isInValidSignature(), is(false));
        assertThat(b.isInValidSignature(), is(false));


        AttackParameter signed = keeper.addOrUpdateParameterValidValue("openid.signed", "");

        signed.setValidValue("a");
        assertThat(a.isInValidSignature(), is(true));
        assertThat(b.isInValidSignature(), is(false));

        signed.setValidValue("b");
        assertThat(a.isInValidSignature(), is(false));
        assertThat(b.isInValidSignature(), is(true));


        signed.setValidValue("a,b");
        assertThat(a.isInValidSignature(), is(true));
        assertThat(b.isInValidSignature(), is(true));
    }

    @Test
    public void testValidSignedCorrectAfterRemove() {
        AttackParameterKeeper keeper = new AttackParameterKeeper();
        AttackParameter a = keeper.addOrUpdateParameterValidValue("openid.a", "one");
        AttackParameter b = keeper.addOrUpdateParameterValidValue("openid.b", "two");


        keeper.addOrUpdateParameterValidValue("openid.signed", "a,b");

        assertThat(a.isInValidSignature(), is(true));
        assertThat(b.isInValidSignature(), is(true));

        keeper.removeParameter("openid.signed");
        assertThat(a.isInValidSignature(), is(false));
        assertThat(b.isInValidSignature(), is(false));
    }

    @Test
    public void testAttackSignedCorrectByModification() {
        AttackParameterKeeper keeper = new AttackParameterKeeper();
        AttackParameter a = keeper.addOrUpdateParameterValidValue("openid.a", "one");
        AttackParameter b = keeper.addOrUpdateParameterValidValue("openid.b", "two");

        assertThat(a.isInValidSignature(), is(false));
        assertThat(b.isInValidSignature(), is(false));


        AttackParameter signed = keeper.addOrUpdateParameterValidValue("openid.signed", "");

        signed.setAttackValue("a");
        assertThat(a.isInAttackSignature(), is(true));
        assertThat(b.isInAttackSignature(), is(false));

        signed.setAttackValue("b");
        assertThat(a.isInAttackSignature(), is(false));
        assertThat(b.isInAttackSignature(), is(true));


        signed.setAttackValue("a,b");
        assertThat(a.isInAttackSignature(), is(true));
        assertThat(b.isInAttackSignature(), is(true));
    }

    @Test
    public void testAttackSignedCorrectAfterRemove() {
        AttackParameterKeeper keeper = new AttackParameterKeeper();
        AttackParameter a = keeper.addOrUpdateParameterValidValue("openid.a", "one");
        AttackParameter b = keeper.addOrUpdateParameterValidValue("openid.b", "two");


        AttackParameter signed = keeper.addOrUpdateParameterValidValue("openid.signed", "");
        signed.setAttackValue("a,b");

        assertThat(a.isInAttackSignature(), is(true));
        assertThat(b.isInAttackSignature(), is(true));

        keeper.removeParameter("openid.signed");
        assertThat(a.isInAttackSignature(), is(false));
        assertThat(b.isInAttackSignature(), is(false));
    }

    @Test
    public void testMoveUp() {
        AttackParameterKeeper keeper = new AttackParameterKeeper();
        AttackParameter a = keeper.addOrUpdateParameterValidValue("openid.a", "one");
        AttackParameter b = keeper.addOrUpdateParameterValidValue("openid.b", "two");

        keeper.moveUp(b);
        assertThat(keeper.getParameter(0), sameInstance(b));
        assertThat(keeper.getParameter(1), sameInstance(a));
    }

    @Test
    public void testMoveDown() {
        AttackParameterKeeper keeper = new AttackParameterKeeper();
        AttackParameter a = keeper.addOrUpdateParameterValidValue("openid.a", "one");
        AttackParameter b = keeper.addOrUpdateParameterValidValue("openid.b", "two");

        keeper.moveDown(a);
        assertThat(keeper.getParameter(0), sameInstance(b));
        assertThat(keeper.getParameter(1), sameInstance(a));
    }

    @Test
    public void testDontMoveUpFirst() {
        AttackParameterKeeper keeper = new AttackParameterKeeper();
        AttackParameter a = keeper.addOrUpdateParameterValidValue("openid.a", "one");
        AttackParameter b = keeper.addOrUpdateParameterValidValue("openid.b", "two");

        keeper.moveUp(a);
        assertThat(keeper.getParameter(0), sameInstance(a));
        assertThat(keeper.getParameter(1), sameInstance(b));
    }

    @Test
    public void testDontMoveDownLast() {
        AttackParameterKeeper keeper = new AttackParameterKeeper();
        AttackParameter a = keeper.addOrUpdateParameterValidValue("openid.a", "one");
        AttackParameter b = keeper.addOrUpdateParameterValidValue("openid.b", "two");

        keeper.moveDown(b);
        assertThat(keeper.getParameter(0), sameInstance(a));
        assertThat(keeper.getParameter(1), sameInstance(b));
    }
}
