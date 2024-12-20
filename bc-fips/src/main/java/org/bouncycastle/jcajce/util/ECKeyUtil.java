package org.bouncycastle.jcajce.util;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import org.bouncycastle.crypto.asymmetric.AsymmetricECPublicKey;
import org.bouncycastle.crypto.fips.FipsEC;

/**
 * Utility class for EC Keys.
 */
public class ECKeyUtil
{
    /**
     * Convert an ECPublicKey into an ECPublicKey which always encodes
     * with point compression.
     *
     * @param ecPublicKey the originating public key.
     * @return a wrapped version of ecPublicKey which uses point compression.
     */
    public static ECPublicKey createKeyWithCompression(ECPublicKey ecPublicKey)
    {
        return new ECPublicKeyWithCompression(ecPublicKey);
    }

    private static class ECPublicKeyWithCompression
        implements ECPublicKey
    {
        private final ECPublicKey ecPublicKey;

        public ECPublicKeyWithCompression(ECPublicKey ecPublicKey)
        {
            this.ecPublicKey = ecPublicKey;
        }

        public ECPoint getW()
        {
            return ecPublicKey.getW();
        }

        public String getAlgorithm()
        {
            return ecPublicKey.getAlgorithm();
        }

        public String getFormat()
        {
            return ecPublicKey.getFormat();
        }

        public byte[] getEncoded()
        {
            AsymmetricECPublicKey ecPubKey = new AsymmetricECPublicKey(FipsEC.ALGORITHM, ecPublicKey.getEncoded());

            return ecPubKey.getEncoded(true);
        }

        public ECParameterSpec getParams()
        {
            return ecPublicKey.getParams();
        }
    }
}
