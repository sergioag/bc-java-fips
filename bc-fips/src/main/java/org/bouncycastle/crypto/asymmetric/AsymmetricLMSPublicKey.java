package org.bouncycastle.crypto.asymmetric;

import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricPublicKey;
import org.bouncycastle.crypto.internal.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.internal.pqc.lms.Composer;
import org.bouncycastle.crypto.internal.pqc.lms.HSSPublicKeyParameters;
import org.bouncycastle.crypto.internal.pqc.lms.LMSPublicKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Leighton-Micali Hash-Based Signatures (LMS) public keys.
 */
public final class AsymmetricLMSPublicKey
    extends AsymmetricLMSKey
    implements AsymmetricPublicKey
{
    private final byte[] keyData;
    private final int hashCode;
    private final AsymmetricKeyParameter lwKey;

    public AsymmetricLMSPublicKey(int levels, byte[] keyData)
    {
        super(levels);

        this.keyData = Arrays.clone(keyData);
        this.hashCode = calculateHashCode();
        this.lwKey = getLwKey(this);
    }

    /**
     * Construct a key from an encoding of a SubjectPublicKeyInfo.
     *
     * @param encoding the DER encoding of the key.
     */
    public AsymmetricLMSPublicKey(byte[] encoding)
        throws IOException
    {
        this(SubjectPublicKeyInfo.getInstance(encoding));
    }

    public AsymmetricLMSPublicKey(SubjectPublicKeyInfo info)
        throws IOException
    {
        this(info.getAlgorithm(), ASN1OctetString.getInstance(info.parsePublicKey()).getOctets());
    }

    private AsymmetricLMSPublicKey(AlgorithmIdentifier algID, byte[] keyEnc)
    {
        super(Pack.bigEndianToInt(keyEnc, 0));

        if (PKCSObjectIdentifiers.id_alg_hss_lms_hashsig.equals(algID.getAlgorithm()))
        {
            this.keyData = Arrays.copyOfRange(keyEnc, 4, keyEnc.length);

            this.hashCode = calculateHashCode();
        }
        else
        {
            throw new IllegalArgumentException("cannot identify key encoding");
        }

        this.lwKey = getLwKey(this);
    }

    public byte[] getPublicData()
    {
        return Arrays.clone(keyData);
    }

    public byte[] getEncoded()
    {
        byte[] encoding = Composer.compose().u32str(L).bytes(keyData).build();

        return KeyUtils.getEncodedSubjectPublicKeyInfo(
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig), new DEROctetString(encoding));
    }

    @Override
    protected Object getInternalKey()
    {
        return lwKey;
    }

    @Override
    public boolean equals(Object o)
    {
        checkApprovedOnlyModeStatus();

        if (this == o)
        {
            return true;
        }

        if (!(o instanceof AsymmetricLMSPublicKey))
        {
            return false;
        }

        AsymmetricLMSPublicKey other = (AsymmetricLMSPublicKey)o;

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

    private static AsymmetricKeyParameter getLwKey(final AsymmetricLMSPublicKey pubKey)
        {
            return AccessController.doPrivileged(new PrivilegedAction<AsymmetricKeyParameter>()
            {
                public AsymmetricKeyParameter run()
                {
                    try
                    {
                        if (pubKey.getL() == 1)
                        {
                            return LMSPublicKeyParameters.getInstance(pubKey.getPublicData());
                        }
                        else
                        {
                            Composer c = Composer.compose().u32str(pubKey.getL()).bytes(pubKey.getPublicData());

                            return HSSPublicKeyParameters.getInstance(c.build());
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
