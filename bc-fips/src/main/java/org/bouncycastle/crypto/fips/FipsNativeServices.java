package org.bouncycastle.crypto.fips;

import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

import org.bouncycastle.crypto.NativeServices;

/**
 * Native services maintains the relationship between implemented native features and
 * the feature definition strings.
 */
class FipsNativeServices
    implements NativeServices
{
    public static final String RSA = "RSA";

    private static Set<String> nativeFeatures = null;

    public String getStatusMessage()
    {

        if (NativeLoader.isNativeLibsAvailableForSystem())
        {
            if (NativeLoader.isNativeInstalled())
            {
                return "READY";
            }
            else
            {
                return NativeLoader.getNativeStatusMessage();
            }
        }

        // No support for platform / architecture
        return "UNSUPPORTED";
    }

    public Set<String> getFeatureSet()
    {
        return getNativeFeatureSet();
    }

    public String getFeatureString()
    {
        return String.join(" ", getFeatureSet());
    }

    public String getVariant()
    {
        return NativeLoader.getSelectedVariant();
    }

    public String[][] getVariantSelectionMatrix()
    {
        try
        {
            return VariantSelector.getFeatureMatrix();
        }
        catch (UnsatisfiedLinkError ule)
        {
        }
        return new String[][]{};
    }

    public boolean hasService(String feature)
    {
        if (nativeFeatures == null)
        {
            nativeFeatures = getNativeFeatureSet();
        }

        return nativeFeatures.contains(feature);
    }

    public String getBuildDate()
    {
        return NativeLibIdentity.getNativeBuiltTimeStamp();
    }

    public String getLibraryIdent()
    {
        String lib = NativeLibIdentity.getLibraryIdent();
        if (lib == null)
        {
            return "java";
        }
        return lib;
    }

    @Override
    public boolean isEnabled()
    {
        return NativeLoader.isNativeEnabled();
    }

    @Override
    public boolean isInstalled()
    {
        return NativeLoader.isNativeInstalled();
    }

    public boolean isSupported()
    {
        return NativeLoader.isNativeLibsAvailableForSystem();
    }

    static synchronized Set<String> getNativeFeatureSet()
    {
        TreeSet<String> set = new TreeSet<>();

        if (NativeFeatures.hasHardwareRSA())
        {
            set.add(RSA);
        }

        if (NativeFeatures.hasHardwareSeed())
        {
            set.add(NRBG);
        }
        if (NativeFeatures.hasHardwareRand())
        {
            set.add(DRBG);
        }

        if (NativeFeatures.hasAESHardwareSupport())
        {
            set.add(AES_ECB);
        }

        if (NativeFeatures.hasGCMHardwareSupport())
        {
            set.add(AES_GCM);
        }

        if (NativeFeatures.hasCBCHardwareSupport())
        {
            set.add(AES_CBC);
        }

        if (NativeFeatures.hasCFBHardwareSupport())
        {
            set.add(AES_CFB);
        }

        if (NativeFeatures.hasCTRHardwareSupport())
        {
            set.add(AES_CTR); // Only AES is needed for CTR mode.
        }

        if (NativeFeatures.hasHardwareSHA())
        {
            set.add(SHA2);
        }

        if (set.isEmpty())
        {
            set.add(NONE);
        }

        return Collections.unmodifiableSet(set);
    }
}
