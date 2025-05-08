package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricPrivateKey;
import org.bouncycastle.crypto.internal.Permissions;
import org.bouncycastle.crypto.internal.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.internal.pqc.lms.Composer;
import org.bouncycastle.crypto.internal.pqc.lms.HSSPrivateKeyParameters;
import org.bouncycastle.crypto.internal.pqc.lms.LMSContextBasedSigner;
import org.bouncycastle.crypto.internal.pqc.lms.LMSPrivateKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Properties;

/**
 * Leighton-Micali Hash-Based Signatures (LMS) private keys.
 */
public final class AsymmetricLMSPrivateKey
    extends AsymmetricLMSKey
    implements AsymmetricPrivateKey
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

    private final byte[] keyData;

    private byte[] publicData;
    private ASN1Set attributes;
    private int hashCode;
    private AsymmetricKeyParameter lwKey;

    public AsymmetricLMSPrivateKey(int levels, byte[] keyData, byte[] publicData)
    {
        super(levels);

        this.keyData = Arrays.clone(keyData);
        this.publicData = Arrays.clone(publicData);
        this.hashCode = calculateHashCode();
        this.lwKey = getLwKey(this);
    }

    /**
     * Construct a key from an encoding of a PrivateKeyInfo.
     *
     * @param encoding the DER encoding of the key.
     */
    public AsymmetricLMSPrivateKey(byte[] encoding)
        throws IOException
    {
        this(PrivateKeyInfo.getInstance(encoding));
    }

    /**
     * Construct a key from a PrivateKeyInfo.
     *
     * @param keyInfo the PrivateKeyInfo containing the key.
     */
    public AsymmetricLMSPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this(ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets(), keyInfo.getPublicKeyData(), keyInfo.getAttributes());
    }

    private AsymmetricLMSPrivateKey(byte[]  keyEnc, ASN1BitString pubKey, ASN1Set attributes)
    {
        this(Pack.bigEndianToInt(keyEnc, 0), keyEnc, pubKey, attributes);
    }

    private AsymmetricLMSPrivateKey(int L, byte[]  keyEnc, ASN1BitString pubKey, ASN1Set attributes)
    {
        super(L);

        this.keyData = Arrays.copyOfRange(keyEnc, 4, keyEnc.length);

        this.attributes = attributes;
        this.hashCode = calculateHashCode();
        this.lwKey = getLwKey(this);

        if (pubKey != null)
        {
            byte[] pubEnc = pubKey.getOctets();

            publicData = Arrays.copyOfRange(pubEnc, 4, pubEnc.length);
        }
        else
        {
            if (this.lwKey instanceof LMSPrivateKeyParameters)
            {
                publicData = ((LMSPrivateKeyParameters)lwKey).getPublicKey().getEncoded();
            }
            else
            {
                publicData = ((HSSPrivateKeyParameters)lwKey).getPublicKey().getLMSPublicKey().getEncoded();
            }
        }
    }

    public long getUsagesRemaining()
    {
        if (lwKey instanceof LMSPrivateKeyParameters)
        {
            return ((LMSPrivateKeyParameters)lwKey).getUsagesRemaining();
        }
        else
        {
            return ((HSSPrivateKeyParameters)lwKey).getUsagesRemaining();
        }
    }

    public long getIndex()
    {
        if (lwKey instanceof LMSPrivateKeyParameters)
        {
            return ((LMSPrivateKeyParameters)lwKey).getIndex();
        }
        else
        {
            return ((HSSPrivateKeyParameters)lwKey).getIndex();
        }
    }

    public byte[] getSecret()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        byte[] kd = Arrays.clone(keyData);

        KeyUtils.checkDestroyed(this);

        return kd;
    }

    public byte[] getPublicData()
    {
        KeyUtils.checkDestroyed(this);

        return Arrays.clone(publicData);
    }

    public AsymmetricLMSPrivateKey extractKeyShard(int usageCount)
    {
        if (lwKey instanceof LMSPrivateKeyParameters)
        {
            LMSPrivateKeyParameters shard = ((LMSPrivateKeyParameters)lwKey).extractKeyShard(usageCount);

            return new AsymmetricLMSPrivateKey(1, shard.getEncoded(), publicData);
        }
        else
        {
            HSSPrivateKeyParameters shard = ((HSSPrivateKeyParameters)lwKey).extractKeyShard(usageCount);

            return new AsymmetricLMSPrivateKey(getL(), shard.getEncoded(), publicData);
        }
    }

    public byte[] getEncoded()
    {
        checkApprovedOnlyModeStatus();

        KeyUtils.checkPermission(Permissions.CanOutputPrivateKey);

        KeyUtils.checkDestroyed(this);

        byte[] encoding = Composer.compose().u32str(L).bytes(keyData).build();
        byte[] pubEncoding = Composer.compose().u32str(L).bytes(publicData).build();

        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
        if (Properties.isOverrideSet("org.bouncycastle.pkcs8.v1_info_only"))
        {
            return KeyUtils.getEncodedPrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes, null);
        }
        else
        {
            return KeyUtils.getEncodedPrivateKeyInfo(algorithmIdentifier, new DEROctetString(encoding), attributes, pubEncoding);
        }
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
            this.attributes = null;
            this.lwKey = null;
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

        if (!(o instanceof AsymmetricLMSPrivateKey))
        {
            return false;
        }

        AsymmetricLMSPrivateKey other = (AsymmetricLMSPrivateKey)o;

        other.checkApprovedOnlyModeStatus();

        if (this.isDestroyed() || other.isDestroyed())
        {
            return false;
        }

        if (!Arrays.constantTimeAreEqual(getSecret(), other.getSecret()))
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

    public LMSContextBasedSigner getContextBasedSigner()
    {
        return (LMSContextBasedSigner)lwKey;
    }

    private static AsymmetricKeyParameter getLwKey(final AsymmetricLMSPrivateKey privKey)
    {
        return AccessController.doPrivileged(new PrivilegedAction<AsymmetricKeyParameter>()
        {
            public AsymmetricKeyParameter run()
            {
                try
                {
                    if (privKey.getL() == 1)
                    {
                        return LMSPrivateKeyParameters.getInstance(privKey.getSecret());
                    }
                    else
                    {
                        return HSSPrivateKeyParameters.getInstance(privKey.getSecret());
                    }
                }
                catch (IOException e)
                {
                    throw new IllegalStateException(e);
                }
            }
        });
    }
}
