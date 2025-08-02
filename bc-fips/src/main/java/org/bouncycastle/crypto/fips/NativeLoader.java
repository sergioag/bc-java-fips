package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

class NativeLoader
{

    private static final Logger LOG = Logger.getLogger(NativeLoader.class.getName());


    public static final String BCFIPS_LIB_CPU_VARIANT = "org.bouncycastle.native.cpu_variant";

    /**
     * Set this property to change the root path where extracted libraries will be stored.
     * By default, they are installed in the system / user temp dir, but on some platforms loading native
     * libraries from system / user temp directories is disabled.
     */
    public static final String LIB_INSTALL_DIR = "org.bouncycastle.native.loader.install_dir";

    private final static AtomicBoolean nativeLibsAvailableForSystem = new AtomicBoolean(false);
    private final static AtomicBoolean nativeInstalled = new AtomicBoolean(false);
    private final static AtomicBoolean nativeEnabled = new AtomicBoolean(false);
    private final static AtomicReference<String> nativeStatusMessage = new AtomicReference<String>("Driver load not attempted");

    private final static AtomicReference<String> selectedVariant = new AtomicReference<>(null);

    private final static FipsNativeServices nativeServices = new FipsNativeServices();

    /**
     * Native has been installed.
     *
     * @return true if the native lib has been installed.
     */
    static synchronized boolean isNativeInstalled()
    {
        return nativeInstalled.get();
    }

    /**
     * Native is available.
     *
     * @return true if native libs have been installed and are NOT disabled.
     */
    static synchronized boolean isNativeAvailable()
    {
        return nativeLibsAvailableForSystem.get() && nativeInstalled.get() && nativeEnabled.get();
    }

    /**
     * Disable native library even if loaded.
     *
     * @param enabled when false will disable the use of native extensions.
     */
    static synchronized void setNativeEnabled(boolean enabled)
    {
        nativeEnabled.set(enabled);
    }

    static synchronized String getNativeStatusMessage()
    {
        return nativeStatusMessage.get();
    }

    static synchronized String getSelectedVariant()
    {
        return selectedVariant.get();
    }


    static String getFile(String path)
    {
        String value;
        try
        {
            InputStream in = NativeLoader.class.getResourceAsStream(path);
            value = Strings.fromByteArray(Streams.readAll(in));
            in.close();
        }
        catch (Exception ex)
        {
            return null;
        }
        return value;
    }


    static List<String> loadVariantsDeps(String depFile, String libName)
    {
        String data = getFile(depFile);
        if (data == null)
        {
            return Collections.emptyList();
        }
        ArrayList<String> out = new ArrayList<>();
        for (String line : data.split("\n"))
        {
            line = line.trim();
            String[] parts = line.split(":");
            if (parts[0].trim().equals(libName))
            {
                out.add(parts[1].trim());
            }
        }
        return Collections.unmodifiableList(out);
    }


    static File installLib(String name, String libPathSegment, String jarPath, File bcLibPath, Set<File> filesInInstallLocation)
    throws Exception
    {

        //
        // Copy nominated dep for library into bcLibPath
        //

        String libLocalName = System.mapLibraryName(name);

        List<String> deps = loadVariantsDeps(jarPath + "/deps.list", libLocalName);
        for (String dep : deps)
        {
            filesInInstallLocation.remove(LoaderUtils.extractFromClasspath(bcLibPath, jarPath + "/" + dep, dep));
        }
        File libToLoad = LoaderUtils.extractFromClasspath(bcLibPath, libPathSegment + "/" + libLocalName, libLocalName);

        filesInInstallLocation.remove(libToLoad);


        return libToLoad;
    }


    static synchronized void loadDriver()
    {

        String forcedVariant = Properties.getPropertyValue(BCFIPS_LIB_CPU_VARIANT);


        // No variants defined at all, or a
        // single variant defined that is java only.
        //
        if ("java".equals(forcedVariant))
        {
            nativeEnabled.set(false);
            nativeInstalled.set(false);
            nativeStatusMessage.set("java support only");
            return;
        }


        String arch_ = Strings.toLowerCase(Properties.getPropertyValue("os.arch", ""));
        String os_ = Strings.toLowerCase(Properties.getPropertyValue("os.name", ""));
        String platform = null;
        String arch = null;

        if (os_.contains("linux"))
        {
            platform = "linux";
        }


        if (platform == null)
        {
            nativeStatusMessage.set("OS '" + os_ + "' is not supported.");
            return;
        }

        if ((arch_.contains("x86") || (arch_.contains("amd")) && arch_.contains("64")))
        {
            arch = "x86_64";
        }


        if (arch == null)
        {
            nativeStatusMessage.set("architecture '" + arch_ + "' is not supported");
            return;
        }

        File bcFipsLibPath;
        try
        {
            String fixedInstallDirProp = Properties.getPropertyValue(LIB_INSTALL_DIR);

            if (fixedInstallDirProp != null)
            {
                String version = BouncyCastleFipsProvider.INFO.substring(BouncyCastleFipsProvider.INFO.lastIndexOf('v') + 1);

                bcFipsLibPath = LoaderUtils.createVersionedTempDir(fixedInstallDirProp, version);
            }
            else
            {
                bcFipsLibPath = LoaderUtils.createTempDir("bc-fips-jni");
            }
        }
        catch (Exception ex)
        {
            LOG.log(Level.FINE, "temporary file creation failed", ex);
            nativeInstalled.set(false);
            nativeStatusMessage.set("temporary file creation failed: " + ex.getMessage());
            bcFipsLibPath = null;
        }

        if (bcFipsLibPath == null)
        {
            return;
        }

        //
        // We track all the existing files in the installation location.
        // During installation, we remove them from this set if they have been replaced.
        // if any files are remaining in the set then there were unaccounted for files in
        // the installation location, and we cannot start the module.
        //
        Set<File> filesInInstallLocation = new HashSet<>();

        Collections.addAll(filesInInstallLocation, bcFipsLibPath.listFiles());


        //
        // Point to the directory in the jar where the native libs are located.
        //
        String jarDir = String.format("/native/%s/%s", platform, arch);


        //
        // Look for a probe library, it matches the platform and architecture.
        // It needs to exist regardless of any forced variant, if it does not exist
        // any forced variant is not going to function anyway.
        //
        String probeLibInJarPath = String.format("/native/%s/%s/probe", platform, arch);

        InputStream tmpIn = NativeLoader.class.getResourceAsStream(probeLibInJarPath + "/" + System.mapLibraryName("bc-probe"));
        if (tmpIn == null)
        {
            String msg = String.format("platform '%s' and architecture '%s' are not supported", platform, arch);
            LOG.log(Level.FINE, msg);
            nativeStatusMessage.set(msg);
            nativeInstalled.set(false);
            return;
        }
        try
        {
            tmpIn.close();
        }
        catch (IOException ignored)
        {
        }


        if (forcedVariant != null)
        {
            selectedVariant.set(forcedVariant);
        }
        else
        {
            try
            {
                // Install probe lib
                File lib = installLib("bc-probe", probeLibInJarPath, jarDir, bcFipsLibPath, filesInInstallLocation);

                AccessController.doPrivileged(
                        new PrivilegedAction<Object>()
                        {
                            @Override
                            public Object run()
                            {
                                System.load(lib.getAbsolutePath());
                                return new Object();
                            }
                        }
                );


            }
            catch (Exception ex)
            {
                LOG.log(Level.FINE, "probe lib failed to load", ex);
                nativeStatusMessage.set("probe lib failed to load " + ex.getMessage());
                nativeInstalled.set(false);
                return;
            }

            try
            {
                selectedVariant.set(VariantSelector.getBestVariantName());
            }
            catch (Throwable ex)
            {
                LOG.log(Level.FINE, "probe lib failed return a variant", ex);
                nativeStatusMessage.set("probe lib failed return a variant " + ex.getMessage());
                nativeInstalled.set(false);
                return;
            }
        }

        if (selectedVariant.get().equals("none"))
        {
            nativeEnabled.set(false);
            nativeInstalled.set(false);
            String msg = "probe returned no suitable CPU features, java support only";
            LOG.log(Level.FINE, msg);
            nativeStatusMessage.set(msg);
            return;
        }


        String variantPathInJar = String.format("/native/%s/%s/%s", platform, arch, selectedVariant);//  variantPaths.get(selectedVariant);

        try
        {
            //
            // Derive the suffix it is the last part of the variant name
            // eg: linux-x86_64-sse has a suffix of "sse"
            //

            File lib = installLib("bc-fips-" + selectedVariant, variantPathInJar, jarDir, bcFipsLibPath, filesInInstallLocation);


            //
            // If not empty we have unexpected files in the library path
            //
            if (!filesInInstallLocation.isEmpty())
            {
                StringBuilder sBld = new StringBuilder();
                for (File f : filesInInstallLocation)
                {
                    if (sBld.length() != 0)
                    {
                        sBld.append(",");
                    }
                    sBld.append(f.getName());
                }
                String msg = String.format("unexpected files in %s: %s", bcFipsLibPath, sBld);
                LOG.log(Level.FINE, msg);
                nativeStatusMessage.set(msg);
                nativeInstalled.set(false);
                return;
            }

            AccessController.doPrivileged(
                    new PrivilegedAction<Object>()
                    {
                        @Override
                        public Object run()
                        {
                            System.load(lib.getAbsolutePath());
                            return new Object();
                        }
                    }
            );

        }
        catch (Exception ex)
        {
            LOG.log(Level.FINE, "native capabilities lib failed to load", ex);
            nativeStatusMessage.set("native capabilities lib failed to load " + ex.getMessage());
            nativeInstalled.set(false);
            return;
        }

        if (!selectedVariant.get().equals(NativeLibIdentity.getLibraryIdent()))
        {
            String msg = String.format("loaded native library variant is %s but the requested library variant is %s", NativeLibIdentity.getLibraryIdent(), selectedVariant);
            LOG.fine(msg);
            nativeStatusMessage.set(msg);
            nativeInstalled.set(false);
            return;
        }

        nativeLibsAvailableForSystem.set(true);
        nativeStatusMessage.set("successfully loaded");
        LOG.fine("successfully loaded");
        nativeInstalled.set(true);
        nativeEnabled.set(true);
    }


    public static boolean isNativeLibsAvailableForSystem()
    {
        return nativeLibsAvailableForSystem.get();
    }

    static FipsNativeServices getNativeServices()
    {
        return nativeServices;
    }

    static boolean hasNativeService(String feature)
    {
        return isNativeAvailable() && nativeServices.hasService(feature);
    }


    private static byte[] takeSHA256Digest(InputStream in)
    {
        try
        {
            byte[] buf = new byte[65535];
            Digest dig = FipsSHS.createBaseDigest(FipsSHS.Algorithm.SHA256);
            int len;
            while ((len = in.read(buf)) >= 0)
            {
                dig.update(buf, 0, len);
            }
            byte[] res = new byte[dig.getDigestSize()];
            dig.doFinal(res, 0);
            return res;
        }
        catch (IOException ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    public static boolean isNativeEnabled()
    {
        return nativeEnabled.get();
    }
}
