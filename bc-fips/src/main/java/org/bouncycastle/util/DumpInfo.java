package org.bouncycastle.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.OutputMACCalculator;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.fips.FipsAES;
import org.bouncycastle.crypto.fips.FipsDH;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.fips.FipsDSA;
import org.bouncycastle.crypto.fips.FipsEC;
import org.bouncycastle.crypto.fips.FipsKDF;
import org.bouncycastle.crypto.fips.FipsPBKD;
import org.bouncycastle.crypto.fips.FipsRSA;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsStatus;
import org.bouncycastle.crypto.fips.FipsTripleDES;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 * Executable class that displays information about the module
 */
public class DumpInfo
{
    private static final String[] classes = new String[] { FipsAES.class.getName(), FipsTripleDES.class.getName(), FipsDH.class.getName(),
        FipsSHS.class.getName(), FipsDRBG.class.getName(), FipsDSA.class.getName(), FipsEC.class.getName(),
        FipsKDF.class.getName(), FipsPBKD.class.getName(), FipsRSA.class.getName() };

    public static void main(String[] args)
    {
        if (args.length > 0)
        {
            if (args[0].equals("-c"))
            {
                System.out.println(Strings.fromByteArray(Hex.encode(FipsStatus.getModuleHMAC())));
                System.err.println("Generated new HMAC");
            }
            else if (args[0].equals("-a") && args.length > 1)
            {
            	try 
            	{
            		JarFile jf = new JarFile(args[1]);
            		System.out.println(Strings.fromByteArray(Hex.encode(calculateModuleHMAC(jf))));
            		System.err.println("Generated new HMAC for Jar file " + args[1]);
            	}
            	catch (IOException e)
            	{
            		System.err.println("Unable to open Jar file " + args[1]);
            	}
            }
            else
            {
            	System.err.println("Invalid command line arguments.");
            }
        }
        else
        {
            runTests();
            System.out.println("Version Info: " + new BouncyCastleFipsProvider().getInfo());
            System.out.println("FIPS Ready Status: " + FipsStatus.getStatusMessage());
            System.out.println("Module SHA-256 HMAC: " + Strings.fromByteArray(Hex.encode(FipsStatus.getModuleHMAC())));
        }
    }

    private static byte[] calculateModuleHMAC(JarFile jarFile)
    {
        // this code is largely the standard approach to self verifying a JCE with some minor modifications. It will calculate
        // the SHA-256 HMAC on the classes.
        try
        {
            OutputMACCalculator hMacCalculator = new FipsSHS.MACOperatorFactory().createOutputMACCalculator(new SymmetricSecretKey(FipsSHS.Algorithm.SHA256_HMAC, Strings.toByteArray(CryptoServicesRegistrar.MODULE_HMAC_KEY)), FipsSHS.SHA256_HMAC);

            UpdateOutputStream mOut = hMacCalculator.getMACStream();

            // build an index to make sure we get things in the same order.
            Map<String, JarEntry> index = new TreeMap<String, JarEntry>();

            for (Enumeration<JarEntry> entries = jarFile.entries(); entries.hasMoreElements();)
            {
                JarEntry jarEntry = entries.nextElement();

                // Skip directories, META-INF, and module-info.class meta-data
                if (jarEntry.isDirectory()
                    || (jarEntry.getName().startsWith("META-INF/") && jarEntry.getName().indexOf("versions") < 0)
                    || jarEntry.getName().indexOf("module-info.class") > 0)
                {
                    continue;
                }

                index.put(jarEntry.getName(), jarEntry);
            }

            byte[] buf = new byte[8192];
            for (Map.Entry<String, JarEntry> entry : index.entrySet())
            {
                JarEntry jarEntry = entry.getValue();
                InputStream is = jarFile.getInputStream(jarEntry);

                // Read in each jar entry. A SecurityException will
                // be thrown if a signature/digest check fails - if that happens
                // we'll just return an empty checksum

                // header information
                byte[] encName = Strings.toUTF8ByteArray(jarEntry.getName());
                mOut.update((byte)0x5B);   // '['
                mOut.update(encName, 0, encName.length);
                mOut.update(Pack.longToBigEndian(jarEntry.getSize()), 0, 8);
                mOut.update((byte)0x5D);    // ']'

                // contents
                int n;
                while ((n = is.read(buf, 0, buf.length)) != -1)
                {
                    mOut.update(buf, 0, n);
                }
                is.close();
            }

            mOut.update((byte)0x5B);   // '['
            byte[] encName = Strings.toUTF8ByteArray("END");
            mOut.update(encName, 0, encName.length);
            mOut.update((byte)0x5D);    // ']'

            mOut.close();

            return hMacCalculator.getMAC();
        }
        catch (Exception e)
        {
            return new byte[32];
        }
    }

    private static void runTests()
    {
        for (String cls : classes)
        {
            if (!FipsStatus.isErrorStatus())
            {
                loadClass(cls);
            }
        }
    }

    private static void loadClass(String className)
    {
        try
        {
            Class.forName(className);
        }
        catch (ExceptionInInitializerError e)
        {
            throw e;
        }
        catch (ClassNotFoundException e)
        {
            throw new IllegalStateException("Unable to initialize module: " + e.getMessage(), e);
        }
    }
}