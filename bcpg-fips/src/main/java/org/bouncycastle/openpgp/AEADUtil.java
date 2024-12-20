package org.bouncycastle.openpgp;

import org.bouncycastle.bcpg.AEADUtils;
import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.crypto.KDFCalculator;
import org.bouncycastle.crypto.fips.FipsKDF;
import org.bouncycastle.crypto.fips.FipsKDFOperatorFactory;

class AEADUtil
{
    /**
     * Derive a message key and IV from the given session key.
     * The result is a byte array containing the key bytes followed by the IV.
     * To split them, use {@link org.bouncycastle.bcpg.AEADUtils#splitMessageKeyAndIv(byte[], int, int)}.
     *
     * @param aeadAlgo   AEAD algorithm
     * @param cipherAlgo symmetric cipher algorithm
     * @param sessionKey session key
     * @param salt       salt
     * @param hkdfInfo   HKDF info
     * @return message key and appended IV
     */
    static byte[] deriveMessageKeyAndIv(int aeadAlgo, int cipherAlgo, byte[] sessionKey, byte[] salt, byte[] hkdfInfo)
    {
        // Is it okay to have this common logic be implemented using BCs lightweight API?
        // Should we move it to BcAEADUtil instead and also provide a JCE implementation?
        FipsKDFOperatorFactory<FipsKDF.AgreementKDFParameters> kdfOpt = new FipsKDF.AgreementOperatorFactory();
        FipsKDF.HKDFKey key = FipsKDF.HKDF_KEY_BUILDER
            .withPrf(FipsKDF.AgreementKDFPRF.SHA256_HMAC)
            .withSalt(salt)
            .build(sessionKey);

        KDFCalculator kdfCalculator = kdfOpt.createKDFCalculator(
            FipsKDF.HKDF.withPRF(key.getPRF()).using(key.getKey()).withIV(hkdfInfo));

        int keyLen = SymmetricKeyUtils.getKeyLengthInOctets(cipherAlgo);
        int ivLen = AEADUtils.getIVLength(aeadAlgo);
        byte[] messageKeyAndIv = new byte[keyLen + ivLen - 8];
        kdfCalculator.generateBytes(messageKeyAndIv, 0, messageKeyAndIv.length);
        return messageKeyAndIv;
    }
}
