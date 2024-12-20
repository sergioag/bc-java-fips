package org.bouncycastle.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.fips.FipsAES;
import org.bouncycastle.jcajce.spec.FPEParameterSpec;

class FPEParametersCreator<T extends ParametersWithIV>
    implements ParametersCreator
{
    private final FipsAES.FPEParameters baseParameters;

    FPEParametersCreator(FipsAES.FPEParameters baseParameters)
    {
        this.baseParameters = baseParameters;
    }

    public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (spec instanceof FPEParameterSpec)
        {
            return baseParameters.withRadix(((FPEParameterSpec)spec).getRadix()).withTweak(((FPEParameterSpec)spec).getTweak())
                                    .withUsingInverseFunction(((FPEParameterSpec)spec).isUsingInverseFunction());
        }

        throw new InvalidAlgorithmParameterException("paramspec required");
    }
}
