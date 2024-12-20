package org.bouncycastle.openpgp.operator.jcajce;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.util.Arrays;

public class JceAEADCipherUtil
{
    static void setUpAeadCipher(Cipher aead, SecretKey secretKey, int mode, byte[] nonce, int aeadMacLen, byte[] aad)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AlgorithmParameterSpec parameters =  new GCMParameterSpec(((aeadMacLen + 7) / 8) * 8, nonce);

        aead.init(mode, secretKey, parameters);
        aead.updateAAD(aad);
    }

    static class GCMParameters
        extends ASN1Object
    {
        private byte[] nonce;
        private int icvLen;

        public GCMParameters(
            byte[] nonce,
            int    icvLen)
        {
            this.nonce = Arrays.clone(nonce);
            this.icvLen = icvLen;
        }

        public byte[] getNonce()
        {
            return Arrays.clone(nonce);
        }

        public int getIcvLen()
        {
            return icvLen;
        }

        public ASN1Primitive toASN1Primitive()
        {
            ASN1EncodableVector v = new ASN1EncodableVector(2);

            v.add(new DEROctetString(nonce));

            if (icvLen != 12)
            {
                v.add(new ASN1Integer(icvLen));
            }

            return new DERSequence(v);
        }
    }
}
