package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

interface AsymmetricKeyInfoConverter
{
    PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException;

    PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException;
}
