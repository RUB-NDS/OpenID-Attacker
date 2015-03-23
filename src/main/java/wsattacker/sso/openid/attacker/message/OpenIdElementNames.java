package wsattacker.sso.openid.attacker.message;

public final class OpenIdElementNames {

    public static final String MODE = "mode";
    public static final String IDENTIFIER = "identifier";
    public static final String CLAIMED_ID = "claimed_id";
    public static final String OP_ENDPOINT = "op_endpoint";
    public static final String ASSOC_HANDLE = "assoc_handle";
    public static final String SIGNATURE = "sig";
    public static final String SIGNED_FIELDS = "signed";
    public static final String NICKNAME = "nickname"; // 'http://axschema.org/namePerson/friendly'
    public static final String EMAIL = "email"; // 'http://axschema.org/contact/email'
    public static final String FULLNAME = "fullname"; // 'http://axschema.org/namePerson'
    public static final String DOB = "dob"; // 'http://axschema.org/birthDate'
    public static final String GENDER = "gender"; // 'http://axschema.org/person/gender'
    public static final String POSTCODE = "postcode"; // 'http://axschema.org/contact/postalCode/home'
    public static final String COUNTRY = "country"; // 'http://axschema.org/contact/country/home'
    public static final String LANGUAGE = "language"; // 'http://axschema.org/pref/language'
    public static final String TIMEZONE = "timezone"; // 'http://axschema.org/pref/timezone'

    private OpenIdElementNames() {
    }
}
