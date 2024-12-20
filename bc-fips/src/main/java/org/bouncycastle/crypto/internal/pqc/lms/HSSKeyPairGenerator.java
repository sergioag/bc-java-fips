/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.pqc.lms;

import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.internal.KeyGenerationParameters;

public class HSSKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    HSSKeyGenerationParameters param;

    public void init(KeyGenerationParameters param)
    {
        this.param = (HSSKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        HSSPrivateKeyParameters privKey = HSS.generateHSSKeyPair(param);

        return new AsymmetricCipherKeyPair(privKey.getPublicKey(), privKey);
    }
}
