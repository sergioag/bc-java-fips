BouncyCastle Java FIPS
======================

This repository contains the source code for the BouncyCastle Java FIPS library in
a buildable form. That is, you can use this repository to build the sources they
provide in source JARs to generate usable JARs.

Why?
====
Unlike the non-FIPS library, the FIPS doesn't have its source code available, except
as source JARs. While this is useful for debugging, it's not useful if you want to build
a custom version to aid in debugging an issue. With this repo, you can build jars suitable
for internal debugging use.

Limitations
===========
First, and foremost, the FIPS certification applies to the binaries provided by BouncyCastle. Thus,
if you use your own version, even if not making any changes, you may not be using a certified
cryptographic module. You may want to assess the compliance implications of this.

Second, while a lot of care has been invested in making sure this is as close as the
real JARs as possible, there's no guarantee that there may be mistakes that may or may
not affect the functionality of the library. Thus, you're using this at your own risk.

Third, this repository contains the code from the source JARs without any modifications, other
than organizing it for build purposes.

Finally, this repository doesn't contain any test suite for the FIPS libraries, since
none is provided. Maybe the test suite for bc-java would be applicable for FIPS to some
extent but, for now, it's out of scope.

Known issues
============
The following is the list of known issues:
- The module-info.class files generated during the build contain the module version in it,
  while the original files don't. Unfortunately, this is the result of a behavior of
  maven-compiler-plugin when it detects that module-info.java exists, and it cannot be disabled.
  However, it doesn't seem to cause any harm so far. Any ideas to fix this would be appreciated.
- The Private-Package header in the manifest for bc-fips project is missing. I've put the
  supposedly correct value for it in the corresponding pom.xml, but it breaks the build.
  Thus, I have left it commented and it shouldn't affect anything because all packages are
  private by default and the Export-Package and Import-Package are generated fine. Any help
  fixing this would be appreciated.
- There is a native component for bc-fips when ran in Linux x86_64. The sources are included
  in this repo, but they are not compiled as part of this build. Instead, the ones present in
  the certified binary are used.

How to build
============

You need to have the following JDK versions installed:
- 1.8
- 9
- 11
- 15

All of these JDKs need to be registered in your `toolchains.xml` file. You can create this
file initially by running: ``mvn toolchains:generate-jdk-toolchains-xml -Dtoolchain.file=/your/home/.m2/toolchains.xml``

If you don't have the required JDK versions, the build will fail very quickly.

For an unsigned build, just running ``mvn package`` will do.

For a signed build, you must have a keystore with the signing cert available. Then you must use the
"sign" profile specifying some additional properties. This is a sample of such command:

```mvn -Psign -Dsign.keystore=your/keystore/file -Dsign.alias=youralias -Dsign.storepass=keystorePassword -Dsign.keypass=certPassword package```

License
=======
The library code falls under the BouncyCastle license, or whatever other license
BouncyCastle decides to use in the future, since it's their code and I don't have
any control over that.

The build files (i.e. pom.xml files) and other misc files are copyrighted by
me (Sergio Aguayo) and fall under the same MIT license as BouncyCastle.

Versions
========

Currently, the following versions are used here:
- Provider: [bc-fips-2.1.0.jar](https://repo1.maven.org/maven2/org/bouncycastle/bc-fips/2.1.0/bc-fips-2.1.0.jar) ``SHA256SUM=caa427f52062e07d0fd6c36eb7d0975dc5c3fa1376f1b611a57c6a1f9d1548d7``
- Provider source: [bc-fips-2.1.0-sources.jar](https://downloads.bouncycastle.org/fips-java/bc-fips-2.1.0-sources.jar) ``SHA256SUM=d848eccdb94579932fe8cc4fa30ed315a0681ed0315acbabe99bcdd12fd95ef5``
- ASN.1 Utility Classes: [bcutil-fips-2.1.4.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcutil-fips/2.1.4/bcutil-fips-2.1.4.jar) ``SHA256SUM=e169519e6441fb19cabf633d44fcef211506793e5be499ac9215648bd20634e0``
- ASN.1 Utility Classes source: [bcutil-fips-2.1.4-sources.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcutil-fips/2.1.4/bcutil-fips-2.1.4-sources.jar) ``SHA256SUM=59e04c70af8d33f7da11fe7014c04f9cddaaca7f280aa006a066d8eaabe8965c``
- PKIX/CMS/EAC/PKCS/OCSP/TSP/OPENSSL: [bcpkix-fips-2.1.9.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcpkix-fips/2.1.9/bcpkix-fips-2.1.9.jar) ``SHA256SUM=c31a4aeeda18f98b06deab50f6c5fa972eb87555ef134268be28eed95fadece7``
- PKIX/CMS/EAC/PKCS/OCSP/TSP/OPENSSL source: [bcpkix-fips-2.1.9-sources.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcpkix-fips/2.1.9/bcpkix-fips-2.1.9-sources.jar) ``SHA256SUM=5bb51e017dd76ac9d4e304f0e353016f466921925bc515ba52ebb60955dcab18``
- SMIME: [bcmail-fips-2.1.6.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcmail-fips/2.1.6/bcmail-fips-2.1.6.jar) ``SHA256SUM=9568345307a8f4bddff50dda1fcbecabe2a011323d2998baa388548a8871e7d8``
- SMIME source: [bcmail-fips-2.1.6-sources.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcmail-fips/2.1.6/bcmail-fips-2.1.6-sources.jar) ``SHA256SUM=7f837bd9749f6c059ee794a99ec51b313d47d4bdf964555389e5b6323fa975c0``
- Jakarta SMIME: [bcjmail-fips-2.1.6.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcjmail-fips/2.1.6/bcjmail-fips-2.1.6.jar) ``SHA256SUM=134bd06e17e66f13319b5e90781695d9c2bd586f4ed1dc3fc6f833279a750bc9``
- Jakarta SMIME source: [bcjmail-fips-2.1.6-sources.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcjmail-fips/2.1.6/bcjmail-fips-2.1.6-sources.jar) ``SHA256SUM=7350bc10ecdb43982abe842266c4c0501672c76e6944d8a877032dc4ef84fa6f``
- OpenPGP/BCPG: [bcpg-fips-2.1.11.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcpg-fips/2.1.11/bcpg-fips-2.1.11.jar) ``SHA256SUM=ea51efee825bd0d61c3d22cff5a127898edc7ca62ba454fbcf4789801031d850``
- OpenPGP/BCPG source: [bcpg-fips-2.1.11-sources.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcpg-fips/2.1.11/bcpg-fips-2.1.11-sources.jar) ``SHA256SUM=24915cdcefbb3b004c5f89143702c0bb02e5298069fda2e87b916ecc40235cbc``
- DTLS/TLS API/JSSE Provider: [bctls-fips-2.1.20.jar](https://repo1.maven.org/maven2/org/bouncycastle/bctls-fips/2.1.20/bctls-fips-2.1.20.jar) ``SHA256SUM=c058a438442ea46d8abdefc95e581ebf2834e50504bda925a945b1f4ceb48d86``
- DTLS/TLS API/JSSE Provider source: [bctls-fips-2.1.20-sources.jar](https://repo1.maven.org/maven2/org/bouncycastle/bctls-fips/2.1.20/bctls-fips-2.1.20-sources.jar) ``SHA256SUM=33d599405cca8e1567f408d0e9df7ec8a774fff4c808467ae5a589db534f025d``

I try to update to new versions as soon as they get published, but there's no
guarantee of the timing or if it will happen at all. 