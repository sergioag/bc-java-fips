package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.internal.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.internal.KeyGenerationParameters;

class Ed25519KeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    public void init(KeyGenerationParameters parameters)
    {
        this.random = parameters.getRandom();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(random);
        Ed25519PublicKeyParameters publicKey = privateKey.generatePublicKey();
        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
