package org.bouncycastle.jcajce.provider;

import java.security.cert.CertificateEncodingException;

import org.bouncycastle.asn1.x509.BasicConstraints;

class X509CertificateInternal extends X509CertificateImpl
{
    private final byte[] encoding;
    private final CertificateEncodingException exception;

    X509CertificateInternal(JcaJceKeyHelper bcHelper, org.bouncycastle.asn1.x509.Certificate c,
                            BasicConstraints basicConstraints, boolean[] keyUsage, String sigAlgName, byte[] sigAlgParams, byte[] encoding,
                            CertificateEncodingException exception)
    {
        super(bcHelper, c, basicConstraints, keyUsage, sigAlgName, sigAlgParams);

        this.encoding = encoding;
        this.exception = exception;
    }

    public byte[] getEncoded() throws CertificateEncodingException
    {
        if (null != exception)
        {
            throw exception;
        }

        if (null == encoding)
        {
            throw new CertificateEncodingException();
        }

        return encoding;
    }
}
