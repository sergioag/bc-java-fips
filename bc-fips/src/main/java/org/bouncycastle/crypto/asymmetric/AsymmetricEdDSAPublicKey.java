package org.bouncycastle.crypto.asymmetric;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.fips.FipsEdEC;
import org.bouncycastle.crypto.general.EdEC;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Edwards Curve Diffie-Hellman (XDH) public keys.
 */
public final class AsymmetricEdDSAPublicKey
    extends AsymmetricEdDSAKey
    implements AsymmetricPublicKey
{
    static final byte[] Ed448Prefix = Hex.decode("3043300506032b6571033a00");
    static final byte[] Ed25519Prefix = Hex.decode("302a300506032b6570032100");

    private static final byte Ed448_type = 0x71;
    private static final byte Ed25519_type = 0x70;

    private final byte[] keyData;
    private final int hashCode;

    public AsymmetricEdDSAPublicKey(Algorithm algorithm, byte[] keyData)
    {
        super(algorithm);
        this.keyData = KeyUtils.isValidEdDSAPublicKey(Arrays.clone(keyData));
        this.hashCode = calculateHashCode();
    }

    /**
     * Construct a key from an encoding of a SubjectPublicKeyInfo.
     *
     * @param encoding the DER encoding of the key.
     */
    public AsymmetricEdDSAPublicKey(byte[] encoding)
    {
        super((encoding[8] == Ed448_type) ? FipsEdEC.Algorithm.Ed448 : FipsEdEC.Algorithm.Ed25519);

        if (encoding[8] == Ed448_type)
        {
            if (KeyUtils.isValidPrefix(Ed448Prefix, encoding)
                && ((encoding.length - Ed448Prefix.length) == EdEC.Ed448_PUBLIC_KEY_SIZE))
            {
                keyData = KeyUtils.isValidEdDSAPublicKey(Arrays.copyOfRange(encoding, Ed448Prefix.length, encoding.length));
            }
            else
            {
                throw new IllegalArgumentException("raw key data not recognised");
            }
        }
        else
        {
            if (KeyUtils.isValidPrefix(Ed25519Prefix, encoding)
                && ((encoding.length - Ed25519Prefix.length) == EdEC.Ed25519_PUBLIC_KEY_SIZE))
            {
                keyData = KeyUtils.isValidEdDSAPublicKey(Arrays.copyOfRange(encoding, Ed25519Prefix.length, encoding.length));
            }
            else
            {
                throw new IllegalArgumentException("raw key data not recognised");
            }
        }

        this.hashCode = calculateHashCode();
    }

    public byte[] getPublicData()
    {
        return Arrays.clone(keyData);
    }

    public byte[] getEncoded()
    {
        if (getAlgorithm().equals(FipsEdEC.Algorithm.Ed448))
        {
            byte[] encoding = new byte[Ed448Prefix.length + keyData.length];

            System.arraycopy(Ed448Prefix, 0, encoding, 0, Ed448Prefix.length);
            System.arraycopy(keyData, 0, encoding, Ed448Prefix.length,  keyData.length);

            return encoding;
        }
        else
        {
            byte[] encoding = new byte[Ed25519Prefix.length + keyData.length];

            System.arraycopy(Ed25519Prefix, 0, encoding, 0, Ed25519Prefix.length);
            System.arraycopy(keyData, 0, encoding, Ed25519Prefix.length, keyData.length);

            return encoding;
        }
    }

    @Override
    public boolean equals(Object o)
    {
        checkApprovedOnlyModeStatus();

        if (this == o)
        {
            return true;
        }

        if (!(o instanceof AsymmetricEdDSAPublicKey))
        {
            return false;
        }

        AsymmetricEdDSAPublicKey other = (AsymmetricEdDSAPublicKey)o;

        if (!Arrays.areEqual(keyData, other.keyData))
        {
            return false;
        }

        return this.getAlgorithm().equals(other.getAlgorithm());
    }

    @Override
    public int hashCode()
    {
        checkApprovedOnlyModeStatus();

        return hashCode;
    }

    private int calculateHashCode()
    {
        int result = getAlgorithm().hashCode();
        result = 31 * result + Arrays.hashCode(keyData);
        return result;
    }
}
