package org.bouncycastle.jcajce.provider;

import java.math.BigInteger;

import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.asymmetric.AsymmetricEdDSAPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricLMSPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricXDHPublicKey;
import org.bouncycastle.crypto.asymmetric.DHDomainParameters;
import org.bouncycastle.crypto.asymmetric.DSADomainParameters;
import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.crypto.asymmetric.GOST3410DomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

class KeyUtil
{
    static void checkDestroyed(Destroyable destroyable)
    {
        if (destroyable.isDestroyed())
        {
            throw new IllegalStateException("key has been destroyed");
        }
    }

    static String generateFingerPrint(BigInteger modulus)
    {
        return new Fingerprint(modulus.toByteArray()).toString();
    }

    static String generateExponentFingerprint(BigInteger exponent)
    {
        return new Fingerprint(exponent.toByteArray(), 32).toString();
    }

    static String destroyedPrivateKeyToString(String algorithm)
    {
        StringBuilder buf = new StringBuilder();
        String nl = Strings.lineSeparator();

        buf.append(algorithm).append(" Private Key [DESTROYED]").append(nl);

        return buf.toString();
    }

    static String privateKeyToString(String algorithm, BigInteger x, DHDomainParameters dhParams)
    {
        StringBuilder buf = new StringBuilder();
        String        nl = Strings.lineSeparator();

        BigInteger y = dhParams.getG().modPow(x, dhParams.getP());

        buf.append(algorithm);
        buf.append(" Private Key [").append(generateKeyFingerprint(y, dhParams)).append("]").append(nl);
        buf.append("              Y: ").append(y.toString(16)).append(nl);

        return buf.toString();
    }

    static String publicKeyToString(String algorithm, BigInteger y, DHDomainParameters dhParams)
    {
        StringBuilder buf = new StringBuilder();
        String        nl = Strings.lineSeparator();

        buf.append(algorithm);
        buf.append(" Public Key [").append(generateKeyFingerprint(y, dhParams)).append("]").append(nl);
        buf.append("             Y: ").append(y.toString(16)).append(nl);

        return buf.toString();
    }

    private static String generateKeyFingerprint(BigInteger y, DHDomainParameters dhParams)
    {
            return new Fingerprint(
                Arrays.concatenate(
                    y.toByteArray(),
                    dhParams.getP().toByteArray(), dhParams.getG().toByteArray())).toString();
    }

    static String privateKeyToString(String algorithm, BigInteger x, DSADomainParameters dsaParams)
    {
        StringBuilder buf = new StringBuilder();
        String        nl = Strings.lineSeparator();

        BigInteger y = dsaParams.getG().modPow(x, dsaParams.getP());

        buf.append(algorithm);
        buf.append(" Private Key [").append(generateKeyFingerprint(y, dsaParams)).append("]").append(nl);
        buf.append("              Y: ").append(y.toString(16)).append(nl);

        return buf.toString();
    }

    static String publicKeyToString(String algorithm, BigInteger y, DSADomainParameters dsaParams)
    {
        StringBuilder buf = new StringBuilder();
        String nl = Strings.lineSeparator();

        buf.append(algorithm);
        buf.append(" Public Key [").append(generateKeyFingerprint(y, dsaParams)).append("]").append(nl);
        buf.append("             Y: ").append(y.toString(16)).append(nl);

        return buf.toString();
    }
     
    private static String generateKeyFingerprint(BigInteger y, DSADomainParameters dsaParams)
    {
            return new Fingerprint(
                Arrays.concatenate(
                    y.toByteArray(),
                    dsaParams.getP().toByteArray(), dsaParams.getQ().toByteArray(), dsaParams.getG().toByteArray())).toString();
    }

    static String privateKeyToString(String algorithm, BigInteger x, GOST3410DomainParameters gostParams)
    {
        StringBuilder buf = new StringBuilder();
        String        nl = Strings.lineSeparator();

        BigInteger y = gostParams.getA().modPow(x, gostParams.getP());

        buf.append(algorithm);
        buf.append(" Private Key [").append(generateKeyFingerprint(y, gostParams)).append("]").append(nl);
        buf.append("                  Y: ").append(y.toString(16)).append(nl);

        return buf.toString();
    }

    static String publicKeyToString(String algorithm, BigInteger y, GOST3410DomainParameters gostParams)
    {
        StringBuilder buf = new StringBuilder();
        String nl = Strings.lineSeparator();

        buf.append(algorithm);
        buf.append(" Public Key [").append(generateKeyFingerprint(y, gostParams)).append("]").append(nl);
        buf.append("                 Y: ").append(y.toString(16)).append(nl);

        return buf.toString();
    }

    private static String generateKeyFingerprint(BigInteger y, GOST3410DomainParameters dhParams)
    {
            return new Fingerprint(
                Arrays.concatenate(
                    y.toByteArray(),
                    dhParams.getP().toByteArray(), dhParams.getA().toByteArray())).toString();
    }

    static String publicKeyToString(String algorithm, org.bouncycastle.math.ec.ECPoint q, ECDomainParameters params)
    {
        StringBuffer buf = new StringBuffer();
        String nl = Strings.lineSeparator();

        buf.append(algorithm);
        buf.append(" Public Key [").append(generateKeyFingerprint(q, params)).append("]").append(nl);
        buf.append("            X: ").append(q.getAffineXCoord().toBigInteger().toString(16)).append(nl);
        buf.append("            Y: ").append(q.getAffineYCoord().toBigInteger().toString(16)).append(nl);

        return buf.toString();
    }

    static String privateKeyToString(String algorithm, BigInteger d, ECDomainParameters params)
    {
        StringBuilder buf = new StringBuilder();
        String        nl = Strings.lineSeparator();

        org.bouncycastle.math.ec.ECPoint q = calculateQ(d, params);

        buf.append(algorithm);
        buf.append(" Private Key [").append(generateKeyFingerprint(q, params)).append("]").append(nl);
        buf.append("            X: ").append(q.getAffineXCoord().toBigInteger().toString(16)).append(nl);
        buf.append("            Y: ").append(q.getAffineYCoord().toBigInteger().toString(16)).append(nl);

        return buf.toString();
    }

    private static org.bouncycastle.math.ec.ECPoint calculateQ(BigInteger d, ECDomainParameters params)
    {
        return params.getG().multiply(d).normalize();
    }

    private static String generateKeyFingerprint(org.bouncycastle.math.ec.ECPoint publicPoint, ECDomainParameters params)
    {
        ECCurve curve = params.getCurve();
        org.bouncycastle.math.ec.ECPoint g = params.getG();

        if (curve != null)
        {
            return new Fingerprint(
                Arrays.concatenate(
                    publicPoint.getEncoded(false),
                    curve.getA().getEncoded(), curve.getB().getEncoded(),
                    g.getEncoded(false))).toString();
        }

        return new Fingerprint(publicPoint.getEncoded(false)).toString();
    }

    static String restrictedToString(String algorithm)
    {
        StringBuilder buf = new StringBuilder();
        String        nl = Strings.lineSeparator();

        buf.append(algorithm);
        buf.append(" Private Key [RESTRICTED]").append(nl);

        return buf.toString();
    }

    static String keyToString(String label, String algorithm, AsymmetricEdDSAPublicKey pubKey)
    {
        StringBuilder buf = new StringBuilder();
        String nl = Strings.lineSeparator();

        byte[] keyBytes = pubKey.getPublicData();

        // -DM Hex.toHexString
        buf.append(algorithm)
            .append(" ")
            .append(label).append(" [")
            .append(new Fingerprint(keyBytes).toString())
            .append("]")
            .append(nl)
            .append("    public data: ")
            .append(Hex.toHexString(keyBytes))
            .append(nl);

        return buf.toString();
    }

    static String keyToString(String label, String algorithm, AsymmetricXDHPublicKey pubKey)
    {
        StringBuilder buf = new StringBuilder();
        String nl = Strings.lineSeparator();

        byte[] keyBytes = pubKey.getPublicData();

        // -DM Hex.toHexString
        buf.append(algorithm)
            .append(" ")
            .append(label).append(" [")
            .append(new Fingerprint(keyBytes).toString())
            .append("]")
            .append(nl)
            .append("    public data: ")
            .append(Hex.toHexString(keyBytes))
            .append(nl);

        return buf.toString();
    }

    static String keyToString(String label, String algorithm, AsymmetricLMSPublicKey pubKey)
    {
        StringBuilder buf = new StringBuilder();
        String nl = Strings.lineSeparator();

        byte[] keyBytes = pubKey.getPublicData();

        // -DM Hex.toHexString
        buf.append(algorithm)
            .append(" ")
            .append(label).append(" [")
            .append(new Fingerprint(keyBytes).toString())
            .append("]")
            .append(nl)
            .append("    public data: ")
            .append(Hex.toHexString(keyBytes))
            .append(nl);

        return buf.toString();
    }
}
