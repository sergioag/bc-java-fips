package org.bouncycastle.jcajce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;

class BasicParametersCreator<T extends Parameters>
    implements ParametersCreator
{
    private final Parameters baseParameters;

    BasicParametersCreator(Parameters baseParameters)
    {
        this.baseParameters = baseParameters;
    }

    public Parameters createParameters(boolean forEncryption, AlgorithmParameterSpec spec, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (spec != null)
        {
            throw new InvalidAlgorithmParameterException("no AlgorithmParameterSpec required");
        }

        return baseParameters;
    }
}
