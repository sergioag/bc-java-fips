package org.bouncycastle.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.jcajce.spec.KMACParameterSpec;

class KMACParametersCreator<T extends FipsSHS.KMACParameters>
    implements MacParametersCreator
{
    private final FipsSHS.KMACParameters baseParameters;

    KMACParametersCreator(FipsSHS.KMACParameters baseParameters)
    {
        this.baseParameters = baseParameters;
    }

    public FipsSHS.KMACParameters getBaseParameters()
    {
        return baseParameters;
    }

    public FipsSHS.KMACParameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (spec instanceof IvParameterSpec)
        {
            return baseParameters.withCustomizationString(((IvParameterSpec)spec).getIV());
        }

        if (spec instanceof KMACParameterSpec)
        {
            KMACParameterSpec kSpec = (KMACParameterSpec)spec;

            return baseParameters.withMACSize(kSpec.getMacSizeInBits()).withCustomizationString(kSpec.getCustomizationString());
        }

        return baseParameters;
    }
}
