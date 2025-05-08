package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.io.DigestOutputStream;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.io.TeeOutputStream;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.jar.JarException;
import java.util.logging.Logger;

class NativeLoader
{

    private static final Logger LOG = Logger.getLogger(NativeLoader.class.getName());


    public static final String BCFIPS_LIB_CPU_VARIANT = "org.bouncycastle.native.cpu_variant";


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
            filesInInstallLocation.remove(copyFromJar(jarPath + "/" + dep, bcLibPath, dep));
        }
        File libToLoad = copyFromJar(libPathSegment + "/" + libLocalName, bcLibPath, libLocalName);

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


        File bcFipsLibPath = AccessController.doPrivileged(new PrivilegedAction<File>()
        {
            @Override
            public File run()
            {


                File ioTmpDir = new File(Properties.getPropertyValue("java.io.tmpdir"));
                if (!ioTmpDir.exists())
                {
                    nativeInstalled.set(false);
                    nativeStatusMessage.set(ioTmpDir + " did not exist");
                    return null;
                }

                File bcFipsLibPath;
                try
                {

                    //
                    // Create a temporary file, we cannot use the inbuilt method as it will attempt to start
                    // an entropy source and the provider is not in a ready state.
                    //
                    File dir = null;
                    long time = System.nanoTime();
                    for (int t = 0; t < 1000; t++)
                    {
                        dir = new File(ioTmpDir, "bc-fips-jni" + Long.toString(time + t, 32) + "-libs");
                        if (dir.mkdirs())
                        {
                            break;
                        }
                        dir = null;
                        Thread.sleep(time % 97);
                    }

                    if (dir == null)
                    {
                        nativeInstalled.set(false);
                        nativeStatusMessage.set("unable to create directory in " + ioTmpDir + " after 1000 unique attempts");
                        return null;
                    }

                    //
                    // Create a directory using that file as a stem
                    //
                    if (!dir.exists())
                    {
                        nativeInstalled.set(false);
                        nativeStatusMessage.set("unable to create temp directory for jni libs: " + dir);
                        return null;
                    }

                    final File tmpDir = dir;

                    //
                    // Shutdown hook clean up installed libraries.
                    //
                    Runtime.getRuntime().addShutdownHook(new Thread(new Runnable()
                    {
                        @Override
                        public void run()
                        {
                            if (!tmpDir.exists())
                            {
                                return;
                            }
                            boolean isDeleted = true;
                            if (tmpDir.isDirectory())
                            {
                                for (File f : tmpDir.listFiles())
                                {
                                    isDeleted &= f.delete();
                                }
                            }

                            isDeleted &= tmpDir.delete();

                            if (!isDeleted)
                            {
                                LOG.fine(" failed to delete: " + tmpDir.getAbsolutePath());
                            }
                            else
                            {
                                LOG.fine("successfully cleaned up: " + tmpDir.getAbsolutePath());
                            }
                        }
                    }));

                    return tmpDir;
                }
                catch (Exception ex)
                {
                    nativeInstalled.set(false);
                    nativeStatusMessage.set("failed because it was not able to create a temporary file in 'java.io.tmpdir' " + ex.getMessage());
                    return null;
                }

            }
        });

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

        for (File f : bcFipsLibPath.listFiles())
        {
            filesInInstallLocation.add(f);
        }


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
            nativeStatusMessage.set(String.format("platform '%s' and architecture '%s' are not supported", platform, arch));
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
                nativeStatusMessage.set("probe lib failed return a variant " + ex.getMessage());
                nativeInstalled.set(false);
                return;
            }
        }

        if ( selectedVariant.get().equals("none"))
        {
            nativeEnabled.set(false);
            nativeInstalled.set(false);
            nativeStatusMessage.set("probe returned no suitable CPU features, java support only");
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
                nativeStatusMessage.set(String.format("unexpected files in %s: %s", bcFipsLibPath.toString(), sBld.toString()));
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
            nativeStatusMessage.set("native capabilities lib failed to load " + ex.getMessage());
            nativeInstalled.set(false);
            return;
        }

        if (!selectedVariant.get().equals(NativeLibIdentity.getLibraryIdent()))
        {
            nativeStatusMessage.set(String.format("loaded native library variant is %s but the requested library variant is %s", NativeLibIdentity.getLibraryIdent(), selectedVariant));
            nativeInstalled.set(false);
            return;
        }

        nativeLibsAvailableForSystem.set(true);
        nativeStatusMessage.set("successfully loaded");
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

    private static File copyFromJar(String inJarPath, File dir, String targetName)
            throws Exception
    {
        InputStream inputStream = NativeLoader.class.getResourceAsStream(inJarPath);
        if (inputStream == null)
        {
            throw new JarException(inJarPath + " lib not found in jar");
        }

        File dest = new File(dir, targetName);

        if (dest.exists())
        {
            //
            // A file already exists check it is the same file.
            // Replacing a ".so" file arbitrarily can cause other JVMS using it to segfault.
            //


            byte[] digestOfOriginalFileInJar = takeSHA256Digest(inputStream);
            inputStream.close();


            FileInputStream fin = new FileInputStream(dest);
            byte[] currentDigest = takeSHA256Digest(fin);
            fin.close();

            if (Arrays.constantTimeAreEqual(currentDigest, digestOfOriginalFileInJar))
            {
                // Same file so do nothing!
                return dest;
            }
            else
            {
                throw new IOException("pre existing file found and is different to file in jar file");
            }

        }


        //
        // Copy file from jar to destination
        //
        FileOutputStream fos = new FileOutputStream(dest);

        Digest dig = FipsSHS.createBaseDigest(FipsSHS.Algorithm.SHA256);
        DigestOutputStream dos = new DigestOutputStream(dig);
        TeeOutputStream tos = new TeeOutputStream(fos, dos);

        Streams.pipeAll(inputStream, tos);
        tos.flush();
        tos.close();
        inputStream.close();

        //
        // Take digest of file after writing to the file system
        //
        FileInputStream fin = new FileInputStream(dest);
        byte[] digestOfSavedFile = takeSHA256Digest(fin);
        fin.close();

        //
        // Check copied file has the same digest as the original in the jar.
        //
        byte[] digestOfOriginalFileInJar = dos.getDigest();

        if (!Arrays.constantTimeAreEqual(digestOfOriginalFileInJar, digestOfSavedFile))
        {
            throw new IOException("file copied from jar does not have same digest as source file in jar");
        }


        return dest;
    }

    public static boolean isNativeEnabled()
    {
        return nativeEnabled.get();
    }
}
