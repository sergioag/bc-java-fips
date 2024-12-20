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
than organizing it for build purposes. Unfortunately, this means that it cannot be used outright,
as described in the "Known issues" section.

Known issues
============
The following is the list of known issues:
- You'll get a "Module checksum failed" exception on startup. This is because there is no
  HMAC.SHA256 file in the generated jars. Generating this file is out of the scope of this
  repository. You can easily modify ``bc-fips/src/main/java/org/bouncycastle/crypto/fips/FipsStatus.java``
  to disable this check. Since one of the goals of this repo is to have the source files
  unchanged when compared to the upstream version, this will never be updated and no PRs
  will be accepted for this.
- The module-info.class files generated during the build contain the module version in it,
  while the original files don't. Unfortunately, this is the result of a behavior of
  maven-compiler-plugin when it detects that module-info.java exists, and it cannot be disabled.
  However, it doesn't seem to cause any harm so far. Any ideas to fix this would be appreciated.

License
=======
The library code falls under the BouncyCastle license, or whatever other license
BouncyCastle decides to use in the future, since it's their code and I don't have
any control over that.

The build files (i.e. pom.xml files) are copyrighted by me (Sergio Aguayo) and fall
under the same MIT license as BouncyCastle.

Versions
========

Currently, the following versions are used here:
- Provider: [bc-fips-2.0.0.jar](https://repo1.maven.org/maven2/org/bouncycastle/bc-fips/2.0.0/bc-fips-2.0.0.jar) ``SHA256SUM=f6a25fd5744e91cc019a9f79733ae757da6648a80946fad9932041ad05695240``
- Provider source: [bc-fips-2.0.0-sources.jar](https://repo1.maven.org/maven2/org/bouncycastle/bc-fips/2.0.0/bc-fips-2.0.0-sources.jar) ``SHA256SUM=26cab04f7353d51b77846dff4daa4e4f8fffefe35b4630a78fc533684cd01920``
- ASN.1 Utility Classes: [bcutil-fips-2.0.3.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcutil-fips/2.0.3/bcutil-fips-2.0.3.jar) ``SHA256SUM=d7ab2fa5ba33594324a2cc26c75fd30e6a13e4d6524cb2027bb8384fd1befa14``
- ASN.1 Utility Classes source: [bcutil-fips-2.0.3-sources.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcutil-fips/2.0.3/bcutil-fips-2.0.3-sources.jar) ``SHA256SUM=0fef304b276c0572c1266888c2665cdc571548e991cc9f67adb1677075e70ea7``
- PKIX/CMS/EAC/PKCS/OCSP/TSP/OPENSSL: [bcpkix-fips-2.0.7.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcpkix-fips/2.0.7/bcpkix-fips-2.0.7.jar) ``SHA256SUM=4471e25adb42e400fd9ffa472d78a40a3b6add49b37cd5945ac2ca62398b16fd``
- PKIX/CMS/EAC/PKCS/OCSP/TSP/OPENSSL source: [bcpkix-fips-2.0.7-sources.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcpkix-fips/2.0.7/bcpkix-fips-2.0.7-sources.jar) ``SHA256SUM=fd71fbab516ff813d7c33af90665e6117626aa3c4e100a59e2e2588065b07f4d``
- SMIME: [bcmail-fips-2.0.5.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcmail-fips/2.0.5/bcmail-fips-2.0.5.jar) ``SHA256SUM=df253d5358722fcb1ca7790ec232c7d2a0283af512ab80ea1fad3474d1254455``
- SMIME source: [bcmail-fips-2.0.5-sources.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcmail-fips/2.0.5/bcmail-fips-2.0.5-sources.jar) ``SHA256SUM=dda01017da1f0c57c8bdffe84edbbf43579fe059b89dfe66430a1a1a341d155b``
- Jakarta SMIME: [bcjmail-fips-2.0.5.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcjmail-fips/2.0.5/bcjmail-fips-2.0.5.jar) ``SHA256SUM=0c785a7f67769b5bab279ee49d6dd2046995d76315341d9a9e744e1409adc531``
- Jakarta SMIME source: [bcjmail-fips-2.0.5-sources.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcjmail-fips/2.0.5/bcjmail-fips-2.0.5-sources.jar) ``SHA256SUM=16131f03c976bda42ac967d045e884ca1005d95dc661779f2d47d7199e7368a0``
- OpenPGP/BCPG: [bcpg-fips-2.0.9.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcpg-fips/2.0.9/bcpg-fips-2.0.9.jar) ``SHA256SUM=a9daf4d3c8d484a510b66dc121db1aafa435504f2aef0fa01ef3a020aae5f3ec``
- OpenPGP/BCPG source: [bcpg-fips-2.0.9-sources.jar](https://repo1.maven.org/maven2/org/bouncycastle/bcpg-fips/2.0.9/bcpg-fips-2.0.9-sources.jar) ``SHA256SUM=912a6e17ea91dc191a9cd01e9ae79c3625af3b0fd1aff8f6a9eb720a6d6cf23f``
- DTLS/TLS API/JSSE Provider: [bctls-fips-2.0.19.jar](https://repo1.maven.org/maven2/org/bouncycastle/bctls-fips/2.0.19/bctls-fips-2.0.19.jar) ``SHA256SUM=0bceb027307098323b0e1365b31bca19caf4f0f20e787d1b48b40be3e6804be0``
- DTLS/TLS API/JSSE Provider source: [bctls-fips-2.0.19-sources.jar](https://repo1.maven.org/maven2/org/bouncycastle/bctls-fips/2.0.19/bctls-fips-2.0.19-sources.jar) ``SHA256SUM=a2248814a5fec8d4aa0650904f63da3a84a307ee4ae7f4c2d6c0354fe4c1b7bb``

I try to update to new versions as soon as they get published, but there's no
guarantee of the timing or if it will happen at all. 