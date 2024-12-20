package org.bouncycastle.crypto.fips;

import java.math.BigInteger;

import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.params.DhuPrivateParameters;
import org.bouncycastle.crypto.internal.params.DhuPublicParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

class DhuBasicAgreement
{
    DhuPrivateParameters privParams;

    public void init(
        CipherParameters key)
    {
        this.privParams = (DhuPrivateParameters)key;
    }

    public int getFieldSize()
    {
        return (privParams.getStaticPrivateKey().getParameters().getP().bitLength() + 7) / 8;
    }

    public byte[] calculateAgreement(CipherParameters pubKey)
    {
        DhuPublicParameters pubParams = (DhuPublicParameters)pubKey;

        if (!privParams.getStaticPrivateKey().getParameters().equals(pubParams.getStaticPublicKey().getParameters()))
        {
            throw new IllegalKeyException("DHU public key components have wrong domain parameters");
        }

        DhBasicAgreement sAgree = new DhBasicAgreement();
        DhBasicAgreement eAgree = new DhBasicAgreement();

        sAgree.init(privParams.getStaticPrivateKey());

        BigInteger sComp = sAgree.calculateAgreement(pubParams.getStaticPublicKey());

        eAgree.init(privParams.getEphemeralPrivateKey());

        BigInteger eComp = eAgree.calculateAgreement(pubParams.getEphemeralPublicKey());
        
        return Arrays.concatenate(
            BigIntegers.asUnsignedByteArray(this.getFieldSize(), eComp),
            BigIntegers.asUnsignedByteArray(this.getFieldSize(), sComp));
    }
}
