package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PSSParameterSpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.util.MessageDigestUtils;

class X509SignatureUtil
{
    private static final ASN1Null       derNull = DERNull.INSTANCE;
    
    static void setSignatureParameters(
        Signature signature,
        ASN1Encodable params)
        throws NoSuchAlgorithmException, SignatureException, InvalidKeyException
    {
        if (params != null && !derNull.equals(params))
        {
            AlgorithmParameters sigParams = AlgorithmParameters.getInstance(signature.getAlgorithm(), signature.getProvider());
            
            try
            {
                sigParams.init(params.toASN1Primitive().getEncoded());
            }
            catch (IOException e)
            {
                throw new SignatureException("IOException decoding parameters: " + e.getMessage());
            }
            
            if (signature.getAlgorithm().endsWith("MGF1"))
            {
                try
                {
                    signature.setParameter(sigParams.getParameterSpec(PSSParameterSpec.class));
                }
                catch (GeneralSecurityException e)
                {                          
                    throw new SignatureException("Exception extracting parameters: " + e.getMessage());
                }
            }
        }
    }
    
    static String getSignatureName(
        AlgorithmIdentifier sigAlgId) 
    {
        ASN1Encodable params = sigAlgId.getParameters();
        
        if (params != null && !derNull.equals(params))
        {
            if (sigAlgId.getAlgorithm().equals(PKCSObjectIdentifiers.id_RSASSA_PSS))
            {
                RSASSAPSSparams rsaParams = RSASSAPSSparams.getInstance(params);
                
                return getDigestName(rsaParams.getHashAlgorithm().getAlgorithm()) + "withRSAandMGF1";
            }
            if (sigAlgId.getAlgorithm().equals(X9ObjectIdentifiers.ecdsa_with_SHA2))
            {
                ASN1Sequence ecDsaParams = ASN1Sequence.getInstance(params);
                
                return getDigestName(ASN1ObjectIdentifier.getInstance(ecDsaParams.getObjectAt(0))) + "withECDSA";
            }
        }

        // to avoid OCD for those who love correct case...
        if (sigAlgId.getAlgorithm().equals(EdECObjectIdentifiers.id_Ed25519))
        {
            return "Ed25519";
        }
        if (sigAlgId.getAlgorithm().equals(EdECObjectIdentifiers.id_Ed448))
        {
            return "Ed448";
        }

        return findAlgName(sigAlgId.getAlgorithm());
    }

    // we need to remove the - to create a correct signature name
    private static String getDigestName(ASN1ObjectIdentifier oid)
    {
        String name = MessageDigestUtils.getDigestName(oid);

        int dIndex = name.indexOf('-');
        if (dIndex > 0 && !name.startsWith("SHA3"))
        {
            return name.substring(0, dIndex) + name.substring(dIndex + 1);
        }

        return name;
    }

    private static String findAlgName(ASN1ObjectIdentifier algOid)
    {
        Provider prov = Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME);

        if (prov != null)
        {
            String algName = lookupAlg(prov, algOid);
            if (algName != null)
            {
                return algName;
            }
        }

        Provider[] provs = Security.getProviders();

        for (int i = 0; i != provs.length; i++)
        {
            if (prov != provs[i])
            {
                String algName = lookupAlg(provs[i], algOid);
                if (algName != null)
                {
                    return algName;
                }
            }
        }

        return algOid.getId();
    }

    private static String lookupAlg(Provider prov, ASN1ObjectIdentifier algOid)
    {
        String      algName = prov.getProperty("Alg.Alias.Signature." + algOid);

        if (algName != null)
        {
            return algName;
        }

        algName = prov.getProperty("Alg.Alias.Signature.OID." + algOid);

        if (algName != null)
        {
            return algName;
        }

        return null;
    }
}
