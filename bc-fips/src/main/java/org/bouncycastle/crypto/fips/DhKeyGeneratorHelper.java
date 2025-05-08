/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.fips;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.internal.params.DhParameters;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.util.BigIntegers;

class DhKeyGeneratorHelper
{
    static final DhKeyGeneratorHelper INSTANCE = new DhKeyGeneratorHelper();

    private DhKeyGeneratorHelper()
    {
    }

    BigInteger calculatePrivate(DhParameters dhParams, SecureRandom random)
    {
        int limit = dhParams.getL();

        if (limit != 0)
        {
            int minWeight = limit >>> 2;
            for (; ; )
            {
                BigInteger x = BigIntegers.createRandomBigInteger(limit, random).setBit(limit - 1);
                if (WNafUtil.getNafWeight(x) >= minWeight)
                {
                    return x;
                }
            }
        }

        BigInteger min = BigIntegers.TWO;
        int m = dhParams.getM();
        if (m != 0)
        {
            min = BigIntegers.ONE.shiftLeft(m - 1);
        }

        BigInteger q = dhParams.getQ();
        if (q == null)
        {
            q = dhParams.getP();
        }
        BigInteger max = q.subtract(BigIntegers.TWO);

        int minWeight = max.bitLength() >>> 2;
        for (; ; )
        {
            BigInteger x = BigIntegers.createRandomInRange(min, max, random);
            if (WNafUtil.getNafWeight(x) >= minWeight)
            {
                return x;
            }
        }
    }

    BigInteger calculatePublic(DhParameters dhParams, BigInteger x)
    {
        return dhParams.getG().modPow(x, dhParams.getP());
    }
}
