package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.NativeServices;

public class FipsNative
{
    private FipsNative()
    {

    }

    public static void setEnabled(boolean enabled)
    {
        NativeLoader.setNativeEnabled(enabled);
    }

    public static boolean isEnabled()
    {
        return NativeLoader.isNativeAvailable();
    }

    public static NativeServices getServices()
    {
        return NativeLoader.getNativeServices();
    }
}
