package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.security.PublicKey;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

class JcaJceKeyHelper
    extends ProviderJcaJceHelper
{
    public JcaJceKeyHelper(BouncyCastleFipsProvider provider)
    {
        super(provider);
    }

    PublicKey convertPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        return ((BouncyCastleFipsProvider)this.provider).getPublicKey(keyInfo);
    }
}
