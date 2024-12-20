package org.bouncycastle.jcajce.provider;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.crypto.BadPaddingException;

/**
 * Holder for things that are not always available...
 */
class ClassUtil
{
    private static final Constructor aeadBadTagConstructor;

    static
    {
        Class aeadBadTagClass = lookup("javax.crypto.AEADBadTagException");
        if (aeadBadTagClass != null)
        {
            aeadBadTagConstructor = findExceptionConstructor(aeadBadTagClass);
        }
        else
        {
            aeadBadTagConstructor = null;
        }
    }

    private static Constructor findExceptionConstructor(Class clazz)
    {
        try
        {
            return clazz.getConstructor(new Class[]{String.class});
        }
        catch (Exception e)
        {
            return null;
        }
    }

    static Class lookup(String className)
    {
        try
        {
            ClassLoader classLoader = ClassUtil.class.getClassLoader();

            if (classLoader == null)
            {
                classLoader = ClassLoader.getSystemClassLoader();
            }
            Class def = classLoader.loadClass(className);

            return def;
        }
        catch (Exception e)
        {
            return null;
        }
    }

    static Method extractMethod(final Class clazz, final String name)
    {
        try
        {
            return (Method)AccessController.doPrivileged(new PrivilegedExceptionAction()
            {
                public Object run()
                    throws Exception
                {
                    return clazz.getDeclaredMethod(name, new Class[0]);
                }
            });
        }
        catch (PrivilegedActionException e)
        {
            return null;
        }
    }

    public static void throwBadTagException(String message)
        throws BadPaddingException
    {
        if (aeadBadTagConstructor != null)
        {
            BadPaddingException aeadBadTag = null;
            try
            {
                aeadBadTag = (BadPaddingException)aeadBadTagConstructor
                        .newInstance(new Object[]{message});
            }
            catch (Exception i)
            {
                // Shouldn't happen, but fall through to BadPaddingException
            }
            if (aeadBadTag != null)
            {
                throw aeadBadTag;
            }
        }

        throw new BadPaddingException(message);
    }
}
