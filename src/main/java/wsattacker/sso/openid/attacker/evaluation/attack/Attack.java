/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sso.openid.attacker.evaluation.attack;

import static java.lang.annotation.ElementType.METHOD;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 *
 * @author christiankossmann
 */
@Target(METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Attack {
    int number() default 0;
    int dependsOnFailureOf() default -1;
}
