package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.SecureRandom;

import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.fips.FipsSecureRandom;
import org.bouncycastle.tls.crypto.TlsNonceGenerator;

class JcaNonceGenerator
    implements TlsNonceGenerator
{
    private final FipsSecureRandom random;

    JcaNonceGenerator(SecureRandom entropySource, byte[] additionalData)
    {
        byte[] nonce = new byte[32];

        entropySource.nextBytes(nonce);

        this.random = FipsDRBG.SHA512.fromEntropySource(entropySource, false)
            .setPersonalizationString(additionalData)
            .build(nonce, false);
    }

    public byte[] generateNonce(int size)
    {
        byte[] nonce = new byte[size];
        random.nextBytes(nonce);
        return nonce;
    }
}
