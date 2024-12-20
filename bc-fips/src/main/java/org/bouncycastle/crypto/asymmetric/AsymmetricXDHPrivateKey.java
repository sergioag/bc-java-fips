package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.Destroyable;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.general.EdEC;
import org.bouncycastle.crypto.internal.Permissions;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

/**
 * Edwards Curve Diffie-Hellman (XDH) private keys.
 */
public final class AsymmetricXDHPrivateKey
    extends AsymmetricXDHKey
    implements Destroyable, AsymmetricPrivateKey
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

    private final byte[] keyData;
    private byte[] publicData;
    private boolean hasPublicKey;

    private ASN1Set attributes;
    private int hashCode;

    public AsymmetricXDHPrivateKey(Algorithm algorithm, byte[] keyData, byte[] publicData)
    {
        super(algorithm);
        this.keyData = Arrays.clone(keyData);
        this.hashCode = calculateHashCode();
        this.attributes = null;
        if (publicData == null)
        {
            this.hasPublicKey = false;
            this.publicData = EdEC.computePublicData(algorithm, keyData);
        }
        else
        {
            this.hasPublicKey = true;
            this.publicData = Arrays.clone(publicData);
        }
    }

    /**
     * Construct a key from an encoding of a PrivateKeyInfo.
     *
     * @param encoding the DER encoding of the key.
     */
    public AsymmetricXDHPrivateKey(byte[] encoding)
        throws IOException
    {
        this(PrivateKeyInfo.getInstance(encoding));
    }

    /**
     * Construct a key from a PrivateKeyInfo.
     *
     * @param keyInfo the PrivateKeyInfo containing the key.
     */
    public AsymmetricXDHPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        super(EdECObjectIdentifiers.id_X448.equals(keyInfo.getPrivateKeyAlgorithm().getAlgorithm())
                    ? EdEC.Algorithm.X448 : EdEC.Algorithm.X25519);

        byte[] infoOcts = keyInfo.getPrivateKey().getOctets();
        if (infoOcts.length == 32 || infoOcts.length == 56) // exact length of X25519/X448 secret used in Java 11
        {
            keyData = Arrays.clone(infoOcts);
        }
        else
        {
            ASN1Encodable keyOcts = keyInfo.parsePrivateKey();
            keyData = Arrays.clone(ASN1OctetString.getInstance(keyOcts).getOctets());
        }

        if (keyInfo.hasPublicKey())
        {
            hasPublicKey = true;
            publicData = Arrays.clone(keyInfo.getPublicKeyData().getOctets());
        }
        else
        {
            publicData = null;
        }

        if (EdECObjectIdentifiers.id_X448.equals(keyInfo.getPrivateKeyAlgorithm().getAlgorithm()))
        {
            if (keyData.length != EdEC.X448_PRIVATE_KEY_SIZE)
            {
                throw new IllegalArgumentException("raw key data incorrect size");
            }
        }
        else
        {
            if (keyData.length != EdEC.X25519_PRIVATE_KEY_SIZE)
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

        byte[] clone = Arrays.clone(keyData);

        KeyUtils.checkDestroyed(this);

        return clone;
    }

    public byte[] getPublicData()
    {
        byte[] clone = Arrays.clone(publicData);

        KeyUtils.checkDestroyed(this);

        return clone;
    }

    public byte[] getEncoded()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        byte[] pubData = (hasPublicKey && !Properties.isOverrideSet("org.bouncycastle.pkcs8.v1_info_only")) ? publicData : null;
        ASN1Set attributes = this.attributes;

        if (getAlgorithm().equals(EdEC.Algorithm.X448))
        {
            return KeyUtils.getEncodedPrivateKeyInfo(
                new AlgorithmIdentifier(EdECObjectIdentifiers.id_X448), new DEROctetString(getSecret()), attributes, pubData);
        }
        else
        {
            return KeyUtils.getEncodedPrivateKeyInfo(
                new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519), new DEROctetString(getSecret()), attributes, pubData);
        }
    }

    protected void zeroize()
    {
        super.zeroize();
        Arrays.clear(keyData);
    }

    public void destroy()
    {
        checkApprovedOnlyModeStatus();

        if (!hasBeenDestroyed.getAndSet(true))
        {
            Arrays.clear(keyData);
            if (publicData != null)
            {
                Arrays.clear(publicData);
            }
            this.publicData = null;
            this.hasPublicKey = false;
            this.attributes = null;
            this.hashCode = -1;
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

        if (!(o instanceof AsymmetricXDHPrivateKey))
        {
            return false;
        }

        AsymmetricXDHPrivateKey other = (AsymmetricXDHPrivateKey)o;

        other.checkApprovedOnlyModeStatus();

        return this.hashCode == other.hashCode
            && KeyUtils.isFieldEqual(this.getAlgorithm(), other.getAlgorithm())
            && Arrays.constantTimeAreEqual(this.keyData, other.keyData);
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

    /*
    @Override
    protected void finalize()
        throws Throwable
    {
        super.finalize();

        //destroy();
    }
     */
}
