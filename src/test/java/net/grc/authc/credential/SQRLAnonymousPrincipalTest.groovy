package net.grc.authc.credential;

import org.apache.commons.codec.binary.Base64;

import spock.lang.Specification
import spock.lang.Unroll;

public class SQRLAnonymousPrincipalTest extends Specification {
    static base64 = new Base64(true);
    static okver = '0'
    static okuri = new URI('qrl://grc.com')
    static okkey = base64.encodeToString([0] * 64 as byte[])

    @Unroll
    def 'test parse #challenge'() {
        def ver = okver
        def key = okkey
        def d = 0

        when:
        def uri = new URI(challenge)
        def pr = new SQRLAnonymousPrincipal(uri,key,d,ver)

        then:
        pr.realm == realm

        where:
        realm                             || challenge
        'sqrl://grc.com'                  || 'sqrl://grc.com/'
        'qrl://grc.com'                   || 'qrl://grc.com/'
        'qrl://grc.com'                   || 'qrl://grc.com'
        'qrl://www.xn--frgbolaget-q5a.nu' || 'qrl://www.xn--frgbolaget-q5a.nu/'
    }

    @Unroll
    def 'RFC 3986 url normalized d=#d #challenge'() {
        def ver = okver
        def key = okkey

        when:
        def uri = new URI(challenge)
        def pr = new SQRLAnonymousPrincipal(uri,key,d,ver)

        then:
        pr.realm == realm

        where:
        challenge                   | d || realm
        'qrl://grc.com:8080'        | 0 || 'qrl://grc.com:8080'
        'qrl://grc.com/a%C2%B1b'    | 9 || 'qrl://grc.com/a%C2%B1b'
        'qrl://grc.com/~sg'         | 4 || 'qrl://grc.com/~sg'
    }

    @Unroll
    def 'RFC 3986 url exception d=#d #challenge'() {
        def ver = okver
        def key = okkey

        when:
        def uri = new URI(challenge)
        def pr = new SQRLAnonymousPrincipal(uri,key,d,ver)

        then:
        thrown(IllegalArgumentException)

        where:
        challenge                   | d || realm
        'qrl://grc.com/a%c2%b1b'    | 9 || 'qrl://grc.com/a%C2%B1b'
        'qrl://grc.com/%7Esg'       | 4 || 'qrl://grc.com/~sg'
        'qrl://grc.com/%44'         | 2 || 'qrl://grc.com/d'
        'qrl://GRC.com'             | 0 || 'qrl://grc.com'
        'qrl://grc.com:80'          | 0 || 'qrl://grc.com'
        'sqrl://grc.com:443'        | 0 || 'sqrl://grc.com'
    }

    @Unroll
    def 'test parse d=#d for #challenge'() {
        def ver = okver
        def key = okkey

        when:
        def uri = new URI(challenge)
        def pr = new SQRLAnonymousPrincipal(uri,key,d,ver)

        then:
        pr.realm == realm

        where:
        realm                             || d | challenge
        'qrl://grc.com/'                  || 1 | 'qrl://grc.com/'
        'qrl://grc.com/login'             || 6 | 'qrl://grc.com/login'
    }

    @Unroll
    def 'test exception for #desc'() {
        when:
        new SQRLAnonymousPrincipal(uri,key,d,ver)

        then:
        thrown(IllegalArgumentException)

        where:
        uri   | key   | d  | ver   | desc
        null  | okkey | 0  | okver | 'no uri'
        okuri | null  | 0  | okver | 'no key'
        okuri | okkey | -1 | okver | 'd < 0'
        okuri | okkey | 0  | null  | 'no ver'
        okuri | okkey | 1  | okver | 'd > path length'

    }

    def 'test draft restrictions'() {
        when:
        new SQRLAnonymousPrincipal(uri,key,d,ver)

        then:
        thrown(IllegalArgumentException)

        where:
        uri   | key   | d  | ver
        okuri | okkey | 0  | '1'
    }
}
