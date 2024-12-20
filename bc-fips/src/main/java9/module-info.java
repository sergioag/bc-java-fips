module org.bouncycastle.fips.core
{
    provides java.security.Provider with org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

    exports org.bouncycastle;
    exports org.bouncycastle.asn1;
    exports org.bouncycastle.asn1.anssi;
    exports org.bouncycastle.asn1.bc;
    exports org.bouncycastle.asn1.cryptopro;
    exports org.bouncycastle.asn1.edec;
    exports org.bouncycastle.asn1.gm;
    exports org.bouncycastle.asn1.gnu;
    exports org.bouncycastle.asn1.iana;
    exports org.bouncycastle.asn1.iso;
    exports org.bouncycastle.asn1.kisa;
    exports org.bouncycastle.asn1.microsoft;
    exports org.bouncycastle.asn1.misc;
    exports org.bouncycastle.asn1.mozilla;
    exports org.bouncycastle.asn1.nist;
    exports org.bouncycastle.asn1.nsri;
    exports org.bouncycastle.asn1.ntt;
    exports org.bouncycastle.asn1.ocsp;
    exports org.bouncycastle.asn1.oiw;
    exports org.bouncycastle.asn1.pkcs;
    exports org.bouncycastle.asn1.rosstandart;
    exports org.bouncycastle.asn1.sec;
    exports org.bouncycastle.asn1.teletrust;
    exports org.bouncycastle.asn1.ua;
    exports org.bouncycastle.asn1.util;
    exports org.bouncycastle.asn1.x500;
    exports org.bouncycastle.asn1.x500.style;
    exports org.bouncycastle.asn1.x509;
    exports org.bouncycastle.asn1.x509.qualified;
    exports org.bouncycastle.asn1.x509.sigi;
    exports org.bouncycastle.asn1.x9;
    exports org.bouncycastle.crypto;
    exports org.bouncycastle.crypto.asymmetric;
    exports org.bouncycastle.crypto.fips;
    exports org.bouncycastle.crypto.general;
    exports org.bouncycastle.crypto.util;
    exports org.bouncycastle.jcajce;
    exports org.bouncycastle.jcajce.io;
    exports org.bouncycastle.jcajce.interfaces;
    exports org.bouncycastle.jcajce.provider;
    exports org.bouncycastle.jcajce.spec;
    exports org.bouncycastle.jcajce.util;
    exports org.bouncycastle.math.ec;
    exports org.bouncycastle.math.ec.custom.sec;
    exports org.bouncycastle.math.ec.endo;
    exports org.bouncycastle.math.ec.rfc7748;
    exports org.bouncycastle.math.ec.rfc8032;
    exports org.bouncycastle.math.field;
    exports org.bouncycastle.util;
    exports org.bouncycastle.util.encoders;
    exports org.bouncycastle.util.io;
    exports org.bouncycastle.util.io.pem;
    exports org.bouncycastle.util.test;

    requires java.logging;
    requires java.naming;
}
