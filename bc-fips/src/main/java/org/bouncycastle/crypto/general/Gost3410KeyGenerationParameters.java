/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.internal.KeyGenerationParameters;

class Gost3410KeyGenerationParameters
    extends KeyGenerationParameters
{
    private Gost3410Parameters params;

    public Gost3410KeyGenerationParameters(
        SecureRandom random,
        Gost3410Parameters params)
    {
        super(random, params.getP().bitLength() - 1);

        this.params = params;
    }

    public Gost3410Parameters getParameters()
    {
        return params;
    }
}
