# OpenID-Attacker
OpenID-Attacker is a free open source security testing tool for the Single Sign-On Protocol OpenID (https://openid.net/specs/openid-authentication-2_0.html).
It is developed by the Chair of Network and Data Security, Ruhr University Bochum (http://nds.rub.de/ ) and the 3curity GmbH (http://3curity.de/ ).

## Building
You can build OpenID-Attacker directly from the Github sources. For this purpose, you need:
- Java 8 or higher
- maven
- git

You procede as follows. You first need to clone OpenID-Attackers sources (you can of course also download a ZIP file):

```bash
$ git clone https://github.com/RUB-NDS/OpenID-Attacker.git 
```

Then you go to the OpenID-Attacker directory and use maven to build and package the files:

```bash
$ cd OpenID-Attacker
$ mvn clean package -DskipTests
```

Afterwards, you are able to go to the runnable directory and execute OpenID-Attacker:

```bash
$ cd runnable
$ java -jar OpenID-Attacker-*.jar
```

## Literature

- The initial version of OpenID-Attacker is described in http://nds.rub.de/media/ei/arbeiten/2014/12/04/OpenIDAttacker.pdf
- Description of attacks on OpenID can be found in http://nds.rub.de/research/publications/openid/
