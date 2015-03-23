package wsattacker.sso.openid.attacker.attack.profile;

import java.util.List;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThat;
import org.junit.Before;
import org.junit.Test;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameter;
import wsattacker.sso.openid.attacker.attack.parameter.AttackParameterKeeper;
import wsattacker.sso.openid.attacker.attack.parameter.utilities.HttpMethod;

public class AttackProfileContainerTest {

    private static final String TEST_PROFILE_DESCRIPTION = "Test Profile Description";
    private static final String TEST_PROFILE_NAME = "Test Profile Name";
    private static AttackProfileContainer profileContainer;
    private static AttackParameterKeeper configuration;
    private static AttackParameter a;

    public AttackProfileContainerTest() {
    }

    @Before
    public void setUp() {
        profileContainer = new AttackProfileContainer();
        configuration = new AttackParameterKeeper();
        a = configuration.addOrUpdateParameterValidValue("a", "a");
        a.setAttackMethod(HttpMethod.POST);
        a.setValidMethod(HttpMethod.POST);
        profileContainer.saveProfile(TEST_PROFILE_NAME, TEST_PROFILE_DESCRIPTION, configuration);
    }

    @Test
    public void testSaveProfile() {
        assertThat(profileContainer.getProfileList(), hasSize(1));
        AttackProfile savedProfile = profileContainer.getProfileList().get(0);
        assertThat(savedProfile.getName(), is(TEST_PROFILE_NAME));
        assertThat(savedProfile.getDescription(), is(TEST_PROFILE_DESCRIPTION));
        AttackParameterKeeper savedKeeper = savedProfile.getConfiguration();
        assertThat(savedKeeper, is(configuration));
        assertThat(savedKeeper, not(sameInstance(configuration)));
    }

    @Test
    public void testUpdateProfile_3args() {
        AttackParameterKeeper keeperBeforeUpdate;
        keeperBeforeUpdate = profileContainer.getProfileList().get(0).getConfiguration();

        int intex = 0;
        String name = "bn";
        String description = "bd";
        profileContainer.updateProfile(intex, name, description);

        assertThat(profileContainer.getProfileList(), hasSize(1));
        AttackProfile savedProfile = profileContainer.getProfileList().get(0);
        assertThat(savedProfile.getName(), is(name));
        assertThat(savedProfile.getDescription(), is(description));
        AttackParameterKeeper savedKeeper = savedProfile.getConfiguration();
        assertThat(savedKeeper, sameInstance(keeperBeforeUpdate));
    }

    @Test
    public void testUpdateProfile_4args() {
        int index = 0;
        String name = "cn";
        String description = "cd";
        AttackParameterKeeper newConfig = new AttackParameterKeeper();
        newConfig.addOrUpdateParameterValidValue("c", "c");

        profileContainer.updateProfile(index, name, description, newConfig);

        assertThat(profileContainer.getProfileList(), hasSize(1));
        AttackProfile savedProfile = profileContainer.getProfileList().get(0);
        assertThat(savedProfile.getName(), is(name));
        assertThat(savedProfile.getDescription(), is(description));
        AttackParameterKeeper savedKeeper = savedProfile.getConfiguration();
        assertThat(savedKeeper, is(newConfig));
        assertThat(savedKeeper, not(sameInstance(newConfig)));
    }

    @Test
    public void testLoadProfileInEmptyKeeper() {
        AttackParameterKeeper toUpdate = new AttackParameterKeeper();
        List<AttackParameter> parameters = toUpdate.getParameterList();
        profileContainer.loadProfile(toUpdate, 0);
        assertThat(toUpdate.getParameterList(), sameInstance(parameters));
        assertThat(toUpdate.getParameterList(), hasSize(1));
    }

    @Test
    public void testLoadProfileInNonEmptyKeeper() {
        AttackParameterKeeper toUpdate = new AttackParameterKeeper();
        toUpdate.addOrUpdateParameterValidValue("z", "z");
        List<AttackParameter> parameters = toUpdate.getParameterList();
        profileContainer.loadProfile(toUpdate, 0);
        assertThat(toUpdate.getParameterList(), sameInstance(parameters));
        assertThat(parameters, hasSize(2));
    }

    @Test
    public void testLoadProfileAndUpdateParameterValues() {
        AttackParameterKeeper toUpdate = new AttackParameterKeeper();
        toUpdate.addOrUpdateParameterValidValue("a", "x");
        List<AttackParameter> parameters = toUpdate.getParameterList();
        profileContainer.loadProfile(toUpdate, 0);
        assertThat(toUpdate.getParameterList(), sameInstance(parameters));
        assertThat(parameters, hasSize(1));
        AttackParameter p = parameters.get(0);
        assertThat(p.getName(), is("a"));
        assertThat(p.getValidValue(), is("a"));
        assertThat(p.getValidMethod(), is(HttpMethod.POST));
        assertThat(p.getAttackMethod(), is(HttpMethod.POST));

    }
}
