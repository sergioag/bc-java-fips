module org.bouncycastle.fips.mail
{
    requires org.bouncycastle.fips.core;
    requires transitive org.bouncycastle.fips.pkix;

    exports org.bouncycastle.mail.smime;
    exports org.bouncycastle.mail.smime.handlers;
    exports org.bouncycastle.mail.smime.util;
    exports org.bouncycastle.mail.smime.validator;
}
