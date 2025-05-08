package org.bouncycastle.crypto.fips;

/**
 * Native methods in this class are implemented by the specific native lib version
 * to identify the library.
 */
class NativeLibIdentity
{
    static String getLibraryIdent()
    {
        try
        {
            return getLibIdent();
        }
        catch (UnsatisfiedLinkError ule)
        {
            return "java";
        }
    }

    private static native String getLibIdent();

    static String getNativeBuiltTimeStamp()
    {
        try
        {
            return getBuiltTimeStamp();
        }
        catch (UnsatisfiedLinkError ule)
        {
            return "None";
        }
    }

    private static native String getBuiltTimeStamp();
}
