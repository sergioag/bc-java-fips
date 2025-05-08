package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.crypto.fips.FipsNonceGenerator;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;

public class BCFipsAEADNonceGenerator
    implements AEADNonceGenerator
{
    private final FipsNonceGenerator nonceGenerator;

    BCFipsAEADNonceGenerator(byte[] baseNonce, int counterBits)
    {
        this.nonceGenerator = new FipsNonceGenerator(baseNonce, counterBits);
    }

    public void generateNonce(byte[] nonce)
        throws TlsFatalAlert
    {
        try
        {
            this.nonceGenerator.generateNonce(nonce);
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
}
