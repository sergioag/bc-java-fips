module org.bouncycastle.fips.tls
{
    provides java.security.Provider with org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
    
    requires java.logging;
    requires org.bouncycastle.fips.core;
    requires org.bouncycastle.fips.util;

    exports org.bouncycastle.jsse;
    exports org.bouncycastle.tls;
    exports org.bouncycastle.jsse.provider;
    exports org.bouncycastle.jsse.java.security;
    exports org.bouncycastle.jsse.util;
    exports org.bouncycastle.tls.crypto;
    exports org.bouncycastle.tls.crypto.impl;
    exports org.bouncycastle.tls.crypto.impl.jcajce;
    exports org.bouncycastle.tls.crypto.impl.jcajce.srp;
}
