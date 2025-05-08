package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.fips.FipsEdEC;
import org.bouncycastle.crypto.general.EdEC;
import org.bouncycastle.crypto.internal.Permissions;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

/**
 * Edwards Curve Diffie-Hellman (EdDSA) private keys.
 */
public final class AsymmetricEdDSAPrivateKey
    extends AsymmetricEdDSAKey
    implements AsymmetricPrivateKey
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

    private final byte[] keyData;

    private boolean hasPublicKey;
    private byte[] publicData;
    private ASN1Set attributes;
    private int hashCode;

    public AsymmetricEdDSAPrivateKey(Algorithm algorithm, byte[] keyData, byte[] publicData)
    {
        super(algorithm);
        this.keyData = Arrays.clone(keyData);
        this.attributes = null;
        if (publicData == null)
        {
            this.hasPublicKey = false;
            this.publicData = FipsEdEC.computePublicData(algorithm, keyData);
        }
        else
        {
            this.hasPublicKey = true;
            this.publicData = Arrays.clone(publicData);
        }
        this.hashCode = calculateHashCode();
    }

    /**
     * Construct a key from an encoding of a PrivateKeyInfo.
     *
     * @param encoding the DER encoding of the key.
     */
    public AsymmetricEdDSAPrivateKey(byte[] encoding)
        throws IOException
    {
        this(PrivateKeyInfo.getInstance(encoding));
    }

    /**
     * Construct a key from a PrivateKeyInfo.
     *
     * @param keyInfo the PrivateKeyInfo containing the key.
     */
    public AsymmetricEdDSAPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        super(EdECObjectIdentifiers.id_Ed448.equals(keyInfo.getPrivateKeyAlgorithm().getAlgorithm())
                    ? FipsEdEC.Algorithm.Ed448 : FipsEdEC.Algorithm.Ed25519);

        ASN1Encodable keyOcts = keyInfo.parsePrivateKey();
        keyData = Arrays.clone(ASN1OctetString.getInstance(keyOcts).getOctets());

        if (keyInfo.hasPublicKey())
        {
            hasPublicKey = true;
            publicData = Arrays.clone(keyInfo.getPublicKeyData().getOctets());
        }
        else
        {
            hasPublicKey = false;
            this.publicData = FipsEdEC.computePublicData(getAlgorithm(), keyData);
        }

        if (EdECObjectIdentifiers.id_Ed448.equals(keyInfo.getPrivateKeyAlgorithm().getAlgorithm()))
        {
            if (keyData.length != EdEC.Ed448_PRIVATE_KEY_SIZE)
            {
                throw new IllegalArgumentException("raw key data incorrect size");
            }
        }
        else
        {
            if (keyData.length != EdEC.Ed25519_PRIVATE_KEY_SIZE)
            {
                throw new IllegalArgumentException("raw key data incorrect size");
            }
        }

        this.attributes = keyInfo.getAttributes();
        this.hashCode = calculateHashCode();
    }

    public byte[] getSecret()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        byte[] rv = Arrays.clone(keyData);

        KeyUtils.checkDestroyed(this);

        return rv;
    }

    public byte[] getPublicData()
    {
        byte[] rv = Arrays.clone(publicData);

        KeyUtils.checkDestroyed(this);

        return rv;
    }

    public byte[] getEncoded()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        KeyUtils.checkDestroyed(this);

        byte[] pubData = (hasPublicKey && !Properties.isOverrideSet("org.bouncycastle.pkcs8.v1_info_only")) ? publicData : null;

        if (getAlgorithm().equals(FipsEdEC.Algorithm.Ed448))
        {
            return KeyUtils.getEncodedPrivateKeyInfo(
                new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448), new DEROctetString(getSecret()), attributes, pubData);
        }
        else
        {
            return KeyUtils.getEncodedPrivateKeyInfo(
                new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), new DEROctetString(getSecret()), attributes, pubData);
        }
    }

    public void destroy()
    {
        checkApprovedOnlyModeStatus();

        if (!hasBeenDestroyed.getAndSet(true))
        {
            Arrays.clear(keyData);
            Arrays.clear(publicData);
            this.publicData = null;
            this.hasPublicKey = false;
            this.attributes = null;
            this.hashCode = -1;
            super.zeroize();
        }
    }

    public boolean isDestroyed()
    {
        checkApprovedOnlyModeStatus();

        return hasBeenDestroyed.get();
    }

    @Override
    public boolean equals(Object o)
    {
        checkApprovedOnlyModeStatus();

        if (this == o)
        {
            return true;
        }

        if (!(o instanceof AsymmetricEdDSAPrivateKey))
        {
            return false;
        }

        AsymmetricEdDSAPrivateKey other = (AsymmetricEdDSAPrivateKey)o;

        other.checkApprovedOnlyModeStatus();

        if (!Arrays.constantTimeAreEqual(keyData, other.keyData))
        {
            return false;
        }

        return this.getAlgorithm().equals(other.getAlgorithm()) & !(this.isDestroyed() | other.isDestroyed());
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
        result = 31 * result + 3 * Arrays.hashCode(publicData);
        return result;
    }
}
