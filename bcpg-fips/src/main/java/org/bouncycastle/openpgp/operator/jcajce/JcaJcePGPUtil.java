package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.crypto.asymmetric.ECDomainParametersIndex;
import org.bouncycastle.crypto.asymmetric.NamedECDomainParameters;
import org.bouncycastle.jcajce.spec.HybridValueParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;

/**
 * Basic utility class
 */
class JcaJcePGPUtil
{
    public static SecretKey makeSymmetricKey(
        int algorithm,
        byte[] keyBytes)
        throws PGPException
    {
        String algName = org.bouncycastle.openpgp.PGPUtil.getSymmetricCipherName(algorithm);

        if (algName == null)
        {
            throw new PGPException("unknown symmetric algorithm: " + algorithm);
        }

        return new SecretKeySpec(keyBytes, algName);
    }

    static ECPoint decodePoint(
        BigInteger encodedPoint,
        ECCurve curve)
        throws IOException
    {
        return curve.decodePoint(BigIntegers.asUnsignedByteArray(encodedPoint));
    }

    static NamedECDomainParameters getX9Parameters(ASN1ObjectIdentifier curveOID)
    {
        return ECDomainParametersIndex.lookupDomainParameters(curveOID);
    }

    static HybridValueParameterSpec getHybridValueParameterSpecWithPrepend(byte[] ephmeralPublicKey, PublicKeyPacket pkp, String algorithmName)
        throws IOException
    {
        throw new UnsupportedOperationException("not yet supported");
        // TODO: update HybridValueParameterSpec
        //return new HybridValueParameterSpec(Arrays.concatenate(ephmeralPublicKey, pkp.getEncoded()), true, new UserKeyingMaterialSpec(Strings.toByteArray("OpenPGP " + algorithmName)));
    }

    static Key getSecret(OperatorHelper helper, PublicKey cryptoPublicKey, String keyEncryptionOID, String agreementName, AlgorithmParameterSpec ukmSpec, Key privKey)
        throws GeneralSecurityException
    {
        KeyAgreement agreement = helper.createKeyAgreement(agreementName);
        agreement.init(privKey, ukmSpec);
        agreement.doPhase(cryptoPublicKey, true);
        return agreement.generateSecret(keyEncryptionOID);
    }

    static boolean isX25519(ASN1ObjectIdentifier curveID)
    {
        return curveID.equals(CryptlibObjectIdentifiers.curvey25519) || curveID.equals(EdECObjectIdentifiers.id_X25519);
    }
}
