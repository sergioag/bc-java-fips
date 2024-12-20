package org.bouncycastle.crypto.fips;

import java.math.BigInteger;

import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.params.EcDhuPrivateParameters;
import org.bouncycastle.crypto.internal.params.EcDhuPublicParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

class EcDhcuBasicAgreement
{
    EcDhuPrivateParameters privParams;

    public void init(
        CipherParameters key)
    {
        this.privParams = (EcDhuPrivateParameters)key;
    }

    public int getFieldSize()
    {
        return (privParams.getStaticPrivateKey().getParameters().getCurve().getFieldSize() + 7) / 8;
    }

    public byte[] calculateAgreement(CipherParameters pubKey)
    {
        EcDhuPublicParameters pubParams = (EcDhuPublicParameters)pubKey;

        EcDhcBasicAgreement sAgree = new EcDhcBasicAgreement();
        EcDhcBasicAgreement eAgree = new EcDhcBasicAgreement();

        sAgree.init(privParams.getStaticPrivateKey());

        BigInteger sComp = sAgree.calculateAgreement(pubParams.getStaticPublicKey());

        eAgree.init(privParams.getEphemeralPrivateKey());

        BigInteger eComp = eAgree.calculateAgreement(pubParams.getEphemeralPublicKey());

        return Arrays.concatenate(
            BigIntegers.asUnsignedByteArray(this.getFieldSize(), eComp),
            BigIntegers.asUnsignedByteArray(this.getFieldSize(), sComp));
    }
}
