package org.bouncycastle.crypto.general;

import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.RawAgreement;

final class X448Agreement
    implements RawAgreement
{
    private X448PrivateKeyParameters privateKey;

    public void init(CipherParameters parameters)
    {
        this.privateKey = (X448PrivateKeyParameters)parameters;
    }

    public int getAgreementSize()
    {
        return X448PrivateKeyParameters.SECRET_SIZE;
    }

    public void calculateAgreement(CipherParameters publicKey, byte[] buf, int off)
    {
        privateKey.generateSecret((X448PublicKeyParameters)publicKey, buf, off);
    }
}
