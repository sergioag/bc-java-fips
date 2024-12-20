package org.bouncycastle.crypto.asymmetric;

import java.math.BigInteger;
import java.security.Permission;
import java.security.SecureRandom;

import javax.security.auth.Destroyable;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.math.internal.Primes;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

class KeyUtils
{
    private static final BigInteger TWO = BigInteger.valueOf(2);

    private static final Algorithm drbgAlg = new Algorithm()
    {
        public String getName()
        {
            return "KeyUtils-DRBG";
        }

        public boolean requiresAlgorithmParameters()
        {
            return false;
        }

        public boolean equals(Object o)
        {
            return o == this;
        }
    };

    private static final byte[] drbgPersonalize = Strings.toByteArray("KeyUtils Prime DRBG");

    static BigInteger validated(DHDomainParameters dhParams, BigInteger y)
    {
        // TLS check
        if (y.compareTo(TWO) < 0 || y.compareTo(dhParams.getP().subtract(TWO)) > 0)
        {
            throw new IllegalArgumentException("Y value is out of range");
        }

        if (dhParams.getQ() != null)
        {
            // FSM_STATE:5.4, "SP 800-56A ASSURANCES", "The module is performing SP 800-56A Assurances self-test"
            // FSM_TRANS:5.16, "CONDITIONAL TEST", "SP 800-56A ASSURANCES CHECK", "Invoke SP 800-56A Assurances test"
            if (BigInteger.ONE.equals(y.modPow(dhParams.getQ(), dhParams.getP())))
            {
                // FSM_TRANS:5.17, "SP 800-56A ASSURANCES CHECK", "CONDITIONAL TEST", "SP 800-56A Assurances test successful"
                return y;
            }
            // FSM_TRANS:5.18, "SP 800-56A ASSURANCES CHECK", "USER COMMAND REJECTED", "SP 800-56A Assurances test failed"
            throw new IllegalArgumentException("Y value does not appear to be in correct group");
        }
        else
        {
            return y;         // we can't really validate without Q.
        }
    }

    static BigInteger validated(DSADomainParameters dsaParams, BigInteger y)
    {
        if (dsaParams != null)
        {
            // FSM_STATE:5.5, "FIPS 186-3/SP 800-89 ASSURANCES", "The module is performing FIPS 186-3/SP 800-89 Assurances self-test"
            // FSM_TRANS:5.13, "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "Invoke FIPS 186-3/SP 800-89 Assurances test"
            if (TWO.compareTo(y) <= 0 && dsaParams.getP().subtract(TWO).compareTo(y) >= 0
                && BigInteger.ONE.equals(y.modPow(dsaParams.getQ(), dsaParams.getP())))
            {
                 // FSM_TRANS:5.14, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 Assurances test successful"
                return y;
            }
            // FSM_TRANS:5.15, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "USER COMMAND REJECTED", "FIPS 186-3/SP 800-89 Assurances test failed"
            throw new IllegalArgumentException("Y value does not appear to be in correct group");
        }
        else
        {
            return y;         // we can't validate without params, fortunately we can't use the key either...
        }
    }

    static BigInteger validated(BigInteger modulus, BigInteger publicExponent)
    {
        // FSM_STATE:5.5, "FIPS 186-3/SP 800-89 ASSURANCES", "The module is performing FIPS 186-3/SP 800-89 Assurances self-test"
        // FSM_TRANS:5.13, "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "Invoke FIPS 186-3/SP 800-89 Assurances test"
        if ((publicExponent.intValue() & 1) == 0)
        {
            // FSM_TRANS:5.15, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "USER COMMAND REJECTED", "FIPS 186-3/SP 800-89 Assurances test failed"
            throw new IllegalArgumentException("RSA publicExponent is even");
        }

        return validatedModulus(modulus);
    }

    static BigInteger validatedModulus(BigInteger modulus)
    {
        // if there is already a marker for this modulus it has already been validated, or we've already loaded it with a private key.
        // skip the tests
        if (!AsymmetricRSAKey.isAlreadySeen(modulus))
        {
            int maxBitLength = Properties.asInteger("org.bouncycastle.rsa.max_size", 15360);

            int modBitLength = modulus.bitLength();
            if (maxBitLength < modBitLength)
            {
                throw new IllegalArgumentException("modulus value out of range");
            }

            if ((modulus.intValue() & 1) == 0)
            {
                // FSM_TRANS:5.15, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "USER COMMAND REJECTED", "FIPS 186-3/SP 800-89 Assurances test failed"
                throw new IllegalArgumentException("RSA modulus is even");
            }

            // the value is the product of the 132 smallest primes from 3 to 751
            if (!modulus.gcd(new BigInteger("145188775577763990151158743208307020242261438098488931355057091965" +
                "931517706595657435907891265414916764399268423699130577757433083166" +
                "651158914570105971074227669275788291575622090199821297575654322355" +
                "049043101306108213104080801056529374892690144291505781966373045481" +
                "8359472391642885328171302299245556663073719855")).equals(BigInteger.ONE))
            {
                // FSM_TRANS:5.15, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "USER COMMAND REJECTED", "FIPS 186-3/SP 800-89 Assurances test failed"
                throw new IllegalArgumentException("RSA modulus has a small prime factor");
            }

            // Use the same iterations as if we were testing a candidate p or q value with error probability 2^-100
            int bits = modulus.bitLength() / 2;
            int iterations = bits >= 1536 ? 3
                : bits >= 1024 ? 4
                : bits >= 512 ? 7
                : 50;

            // SP 800-89 requires use of an approved DRBG.
            SecureRandom testRandom = FipsDRBG.fetchBasicDRBG(drbgAlg, FipsDRBG.SHA256, drbgPersonalize);

            Primes.MROutput mr = Primes.enhancedMRProbablePrimeTest(modulus, testRandom, iterations);
            if (!mr.isProvablyComposite())
            {
                // FSM_TRANS:5.15, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "USER COMMAND REJECTED", "FIPS 186-3/SP 800-89 Assurances test failed"
                throw new IllegalArgumentException("RSA modulus is not composite");
            }
            if (!mr.isNotPrimePower())
            {
                // FSM_TRANS:5.15, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "USER COMMAND REJECTED", "FIPS 186-3/SP 800-89 Assurances test failed"
                throw new IllegalArgumentException("RSA modulus is a power of a prime");
            }
        }
        // FSM_TRANS:5.14, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 Assurances test successful"

        return modulus;
    }

    static ECPoint validated(ECCurve c, ECPoint q)
    {
        // FSM_STATE:5.5, "FIPS 186-3/SP 800-89 ASSURANCES", "The module is performing FIPS 186-3/SP 800-89 Assurances self-test"
        // FSM_TRANS:5.13, "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "Invoke FIPS 186-3/SP 800-89 Assurances test"
        if (q == null)
        {
            // FSM_TRANS:5.15, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "USER COMMAND REJECTED", "FIPS 186-3/SP 800-89 Assurances test failed"
            throw new IllegalArgumentException("Point has null value");
        }

        q = ECAlgorithms.importPoint(c, q).normalize();

        if (q.isInfinity())
        {
            // FSM_TRANS:5.15, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "USER COMMAND REJECTED", "FIPS 186-3/SP 800-89 Assurances test failed"
            throw new IllegalArgumentException("Point at infinity");
        }

        if (!q.isValid())
        {
            // FSM_TRANS:5.15, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "USER COMMAND REJECTED", "FIPS 186-3/SP 800-89 Assurances test failed"
            throw new IllegalArgumentException("Point not on curve");
        }

        // FSM_TRANS:5.14, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 Assurances test successful"
        return q;
    }

    static ECPoint validated(ECCurve c, byte[] encodedPoint)
    {
        // FSM_STATE:5.5, "FIPS 186-3/SP 800-89 ASSURANCES", "The module is performing FIPS 186-3/SP 800-89 Assurances self-test"
        // FSM_TRANS:5.13, "CONDITIONAL TEST", "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "Invoke FIPS 186-3/SP 800-89 Assurances test"
        if (encodedPoint == null)
        {
            // FSM_TRANS:5.15, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "USER COMMAND REJECTED", "FIPS 186-3/SP 800-89 Assurances test failed"
            throw new IllegalArgumentException("Point encoding has null value");
        }

        ECPoint q = c.decodePoint(encodedPoint);

        if (q == null)
        {
            // FSM_TRANS:5.15, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "USER COMMAND REJECTED", "FIPS 186-3/SP 800-89 Assurances test failed"
            throw new IllegalArgumentException("Point has null value");
        }

        q = q.normalize();

        if (q.isInfinity())
        {
            // FSM_TRANS:5.15, "FIPS 186-3/SP 800-89 ASSURANCES CHECK", "USER COMMAND REJECTED", "FIPS 186-3/SP 800-89 Assurances test failed"
            throw new IllegalArgumentException("Point at infinity");
        }

        return q;
    }

    static boolean isNotNull(ASN1Encodable parameters)
    {
        return parameters != null && !DERNull.INSTANCE.equals(parameters.toASN1Primitive());
    }

    static X962Parameters buildCurveParameters(ECDomainParameters curveParams)
    {
        X962Parameters          params;

        if (curveParams instanceof NamedECDomainParameters)
        {
            params = new X962Parameters(((NamedECDomainParameters)curveParams).getID());
        }
        else if (curveParams instanceof ECImplicitDomainParameters)
        {
            params = new X962Parameters(DERNull.INSTANCE);
        }
        else
        {
            X9ECParameters ecP = new X9ECParameters(
                curveParams.getCurve(),
                new X9ECPoint(curveParams.getG(), false),
                curveParams.getN(),
                curveParams.getH(),
                curveParams.getSeed());

            params = new X962Parameters(ecP);
        }

        return params;
    }

    static int getOrderBitLength(ECDomainParameters curveParams)
    {
        return curveParams.getN().bitLength();
    }

    static boolean isDHPKCSParam(ASN1Encodable params)
    {
        ASN1Sequence seq = ASN1Sequence.getInstance(params);

        if (seq.size() == 2)
        {
            return true;
        }

        if (seq.size() > 3)
        {
            return false;
        }

        ASN1Integer l = ASN1Integer.getInstance(seq.getObjectAt(2));
        ASN1Integer p = ASN1Integer.getInstance(seq.getObjectAt(0));

        if (l.getValue().compareTo(BigInteger.valueOf(p.getValue().bitLength())) > 0)
        {
            return false;
        }

        return true;
    }

    static byte[] getEncodedInfo(ASN1Object info)
    {
         try
         {
             return info.getEncoded(ASN1Encoding.DER);
         }
         catch (Exception e)
         {
             return null;
         }
    }

    static byte[] getEncodedSubjectPublicKeyInfo(AlgorithmIdentifier algId, ASN1Encodable pubKey)
    {
         try
         {
             SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(algId, pubKey.toASN1Primitive());

             return getEncodedInfo(info);
         }
         catch (Exception e)
         {
             return null;
         }
    }

    static byte[] getEncodedPrivateKeyInfo(AlgorithmIdentifier algId, ASN1Encodable privKey)
    {
         try
         {
             PrivateKeyInfo info = new PrivateKeyInfo(algId, privKey.toASN1Primitive());

             return getEncodedInfo(info);
         }
         catch (Exception e)
         {
             return null;
         }
    }

    static byte[] getEncodedPrivateKeyInfo(AlgorithmIdentifier algId, ASN1Encodable privKey, ASN1Set attributes, byte[] publicKey)
    {
         try
         {
             PrivateKeyInfo info = new PrivateKeyInfo(algId, privKey.toASN1Primitive(), attributes, publicKey);

             return getEncodedInfo(info);
         }
         catch (Exception e)
         {
             return null;
         }
    }

    static void checkDestroyed(Destroyable destroyable)
    {
        if (destroyable.isDestroyed())
        {
            throw new IllegalStateException("key has been destroyed");
        }
    }

    static void checkPermission(final Permission keyPermission)
    {
        final SecurityManager securityManager = System.getSecurityManager();

        if (securityManager != null)
        {
            securityManager.checkPermission(keyPermission);
        }
    }

    static boolean isValidPrefix(byte[] prefix, byte[] encoding)
    {
        if (encoding.length < prefix.length)
        {
            return !isValidPrefix(prefix, prefix);
        }

        int nonEqual = 0;

        for (int i = 0; i != prefix.length; i++)
        {
            nonEqual |= (prefix[i] ^ encoding[i]);
        }

        return nonEqual == 0;
    }

    static byte[] isValidEdDSAPublicKey(byte[] keyData)
    {
        if (keyData.length == Ed25519.PUBLIC_KEY_SIZE)
        {
            if (!Ed25519.validatePublicKeyFull(keyData, 0))
            {
                throw new IllegalArgumentException("invalid Ed25519 public key data");
            }
        }
        else if (keyData.length == Ed448.PUBLIC_KEY_SIZE)
        {
            if (!Ed448.validatePublicKeyFull(keyData, 0))
            {
                throw new IllegalArgumentException("invalid Ed448 public key data");
            }
        }
        else
        {
            throw new IllegalArgumentException("public key data wrong length");
        }

        return keyData;
    }

    // always return false if either object is null
    static boolean isFieldEqual(Object a, Object b)
    {
        return a != null && a.equals(b);
    }
}
