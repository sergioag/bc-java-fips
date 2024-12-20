package org.bouncycastle.crypto.asymmetric;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.general.EdEC;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Edwards Curve Diffie-Hellman (XDH) public keys.
 */
public final class AsymmetricXDHPublicKey
    extends AsymmetricXDHKey
    implements AsymmetricPublicKey
{
    static final byte[] x448Prefix = Hex.decode("3042300506032b656f033900");
    static final byte[] x25519Prefix = Hex.decode("302a300506032b656e032100");

    private static final byte x448_type = 0x6f;
    private static final byte x25519_type = 0x6e;

    private final byte[] keyData;
    private final int hashCode;

    public AsymmetricXDHPublicKey(Algorithm algorithm, byte[] keyData)
    {
        super(algorithm);
        this.keyData = Arrays.clone(keyData);
        this.hashCode = calculateHashCode();
    }

    /**
     * Construct a key from an encoding of a SubjectPublicKeyInfo.
     *
     * @param encoding the DER encoding of the key.
     */
    public AsymmetricXDHPublicKey(byte[] encoding)
    {
        super((encoding[8] == x448_type) ? EdEC.Algorithm.X448 : EdEC.Algorithm.X25519);

        if (encoding[8] == x448_type)
        {
            if (KeyUtils.isValidPrefix(x448Prefix, encoding)
                && ((encoding.length - x448Prefix.length) == EdEC.X448_PUBLIC_KEY_SIZE))
            {
                keyData = Arrays.copyOfRange(encoding, x448Prefix.length, encoding.length);
            }
            else
            {
                throw new IllegalArgumentException("raw key data not recognised");
            }
        }
        else
        {
            if (KeyUtils.isValidPrefix(x25519Prefix, encoding)
                && ((encoding.length - x25519Prefix.length) == EdEC.X25519_PUBLIC_KEY_SIZE))
            {
                keyData = Arrays.copyOfRange(encoding, x25519Prefix.length, encoding.length);
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
        if (getAlgorithm().equals(EdEC.Algorithm.X448))
        {
            byte[] encoding = new byte[x448Prefix.length + keyData.length];

            System.arraycopy(x448Prefix, 0, encoding, 0, x448Prefix.length);
            System.arraycopy(keyData, 0, encoding, x448Prefix.length, keyData.length);

            return encoding;
        }
        else
        {
            byte[] encoding = new byte[x25519Prefix.length + keyData.length];

            System.arraycopy(x25519Prefix, 0, encoding, 0, x25519Prefix.length);
            System.arraycopy(keyData, 0, encoding, x25519Prefix.length, keyData.length);

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

        if (!(o instanceof AsymmetricXDHPublicKey))
        {
            return false;
        }

        AsymmetricXDHPublicKey other = (AsymmetricXDHPublicKey)o;

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
