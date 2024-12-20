module org.bouncycastle.fips.pg
{
    requires org.bouncycastle.fips.core;

    exports org.bouncycastle.bcpg;
    exports org.bouncycastle.gpg;
    exports org.bouncycastle.openpgp;
    exports org.bouncycastle.bcpg.attr;
    exports org.bouncycastle.bcpg.sig;
    exports org.bouncycastle.gpg.keybox;
    exports org.bouncycastle.gpg.keybox.jcajce;
    exports org.bouncycastle.openpgp.jcajce;
    exports org.bouncycastle.openpgp.operator;
    exports org.bouncycastle.openpgp.operator.jcajce;
}
