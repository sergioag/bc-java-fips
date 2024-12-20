package org.bouncycastle.jcajce.provider;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;

class ChaCha20SpecUtil
{
    private static final Class chaCha20Spec = ClassUtil.lookup("javax.crypto.spec.ChaCha20ParameterSpec");

    static final Method counter;
    static final Method nonce;

    static
    {
        if (chaCha20Spec != null)
        {
            counter = ClassUtil.extractMethod(chaCha20Spec, "getCounter");
            nonce = ClassUtil.extractMethod(chaCha20Spec, "getNonce");
        }
        else
        {
            counter = null;
            nonce = null;
        }
    }

    static boolean chacha20SpecExists()
    {
        return chaCha20Spec != null;
    }

    static boolean isChaCha20Spec(AlgorithmParameterSpec paramSpec)
    {
        return chaCha20Spec != null && chaCha20Spec.isInstance(paramSpec);
    }

    static boolean isChaCha20Spec(Class paramSpecClass)
    {
        return chaCha20Spec == paramSpecClass;
    }

    static Class[] getCipherSpecClasses()
    {
        if (chacha20SpecExists())
        {
            return new Class[]{ChaCha20SpecUtil.chaCha20Spec, IvParameterSpec.class};
        }
        else
        {
            return new Class[]{IvParameterSpec.class};
        }
    }

    static AlgorithmParameterSpec extractChaCha20Spec(final ASN1Primitive spec)
        throws InvalidParameterSpecException
    {
        Object rv = AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                try
                {
                    ASN1OctetString chacha20Params = ASN1OctetString.getInstance(spec);
                    Constructor constructor = chaCha20Spec.getConstructor(new Class[]{byte[].class, Integer.TYPE});

                    return constructor.newInstance(new Object[]{ chacha20Params.getOctets(), 0 });
                }
                catch (NoSuchMethodException e)
                {
                    return new InvalidParameterSpecException("no constructor found!");   // should never happen
                }
                catch (Exception e)
                {
                    return new InvalidParameterSpecException("construction failed: " + e.getMessage());   // should never happen
                }
            }
        });
        if (rv instanceof AlgorithmParameterSpec)
        {
            return (AlgorithmParameterSpec)rv;
        }
        else
        {
            throw (InvalidParameterSpecException)rv;
        }
    }

    static ASN1Sequence extractChaCha20Parameters(final AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException
    {
        Object rv = AccessController.doPrivileged(new PrivilegedAction<Object>()
        {
            public Object run()
            {
                try
                {
                    return new DERSequence(new ASN1Encodable[]{
                        new DEROctetString((byte[])nonce.invoke(paramSpec, new Object[0])),
                        new ASN1Integer((Integer)counter.invoke(paramSpec, new Object[0]))
                    });
                }
                catch (Exception e)
                {
                    return new InvalidParameterSpecException("cannot process ChaCha20ParameterSpec: " + e.getMessage());
                }
            }
        });
        if (rv instanceof ASN1Sequence)
        {
            return (ASN1Sequence)rv;
        }
        else
        {
            throw (InvalidParameterSpecException)rv;
        }
    }
}
