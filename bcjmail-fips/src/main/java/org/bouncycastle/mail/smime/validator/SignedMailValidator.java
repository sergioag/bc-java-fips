package org.bouncycastle.mail.smime.validator;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.mail.Address;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaX509CertSelectorConverter;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.pkix.jcajce.CertPathReviewerException;
import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;
import org.bouncycastle.pkix.util.ErrorBundle;
import org.bouncycastle.pkix.util.filter.TrustedInput;
import org.bouncycastle.pkix.util.filter.UntrustedInput;
import org.bouncycastle.util.Integers;

public class SignedMailValidator
{
    private static final String RESOURCE_NAME = "org.bouncycastle.mail.smime.validator.SignedMailValidatorMessages";

    private static final Class DEFAULT_CERT_PATH_REVIEWER = PKIXCertPathReviewer.class;

    private static final String EXT_KEY_USAGE = Extension.extendedKeyUsage
        .getId();

    private static final String SUBJECT_ALTERNATIVE_NAME = Extension.subjectAlternativeName
        .getId();

    private static final int shortKeyLength = 512;

    // (365.25*30)*24*3600*1000
    private static final long THIRTY_YEARS_IN_MILLI_SEC = 21915l * 12l * 3600l * 1000l;

    private static final JcaX509CertSelectorConverter selectorConverter = new JcaX509CertSelectorConverter();

    private CertStore certs;

    private SignerInformationStore signers;

    private Map results;

    private String[] fromAddresses;

    private Class certPathReviewerClass;

    /**
     * Validates the signed {@link MimeMessage} message. The
     * {@link PKIXParameters} from param are used for the certificate path
     * validation. The actual PKIXParameters used for the certificate path
     * validation is a copy of param with the followin changes: <br> - The
     * validation date is changed to the signature time <br> - A CertStore with
     * certificates and crls from the mail message is added to the CertStores.<br>
     * <br>
     * In <code>param</code> it's also possible to add additional CertStores
     * with intermediate Certificates and/or CRLs which then are also used for
     * the validation.
     *
     * @param message the signed MimeMessage
     * @param param   the parameters for the certificate path validation
     * @throws SignedMailValidatorException if the message is no signed message or if an exception occurs
     * reading the message
     */
    public SignedMailValidator(MimeMessage message, PKIXParameters param)
        throws SignedMailValidatorException
    {
        this(message, param, DEFAULT_CERT_PATH_REVIEWER);
    }

    /**
     * Validates the signed {@link MimeMessage} message. The
     * {@link PKIXParameters} from param are used for the certificate path
     * validation. The actual PKIXParameters used for the certificate path
     * validation is a copy of param with the followin changes: <br> - The
     * validation date is changed to the signature time <br> - A CertStore with
     * certificates and crls from the mail message is added to the CertStores.<br>
     * <br>
     * In <code>param</code> it's also possible to add additional CertStores
     * with intermediate Certificates and/or CRLs which then are also used for
     * the validation.
     *
     * @param message               the signed MimeMessage
     * @param param                 the parameters for the certificate path validation
     * @param certPathReviewerClass a subclass of {@link PKIXCertPathReviewer}. The SignedMailValidator
     *                              uses objects of this type for the cert path vailidation. The class must
     *                              have an empty constructor.
     * @throws SignedMailValidatorException if the message is no signed message or if an exception occurs
     * reading the message
     * @throws IllegalArgumentException if the certPathReviewerClass is not a
     * subclass of {@link PKIXCertPathReviewer} or objects of
     * certPathReviewerClass can not be instantiated
     */
    public SignedMailValidator(MimeMessage message, PKIXParameters param, Class certPathReviewerClass)
        throws SignedMailValidatorException
    {
        this.certPathReviewerClass = certPathReviewerClass;
        boolean isSubclass = DEFAULT_CERT_PATH_REVIEWER.isAssignableFrom(certPathReviewerClass);
        if (!isSubclass)
        {
            throw new IllegalArgumentException("certPathReviewerClass is not a subclass of " + DEFAULT_CERT_PATH_REVIEWER.getName());
        }

        SMIMESigned s;

        try
        {
            // check if message is multipart signed
            if (message.isMimeType("multipart/signed"))
            {
                MimeMultipart mimemp = (MimeMultipart)message.getContent();
                s = new SMIMESigned(mimemp);
            }
            else if (message.isMimeType("application/pkcs7-mime")
                || message.isMimeType("application/x-pkcs7-mime"))
            {
                s = new SMIMESigned(message);
            }
            else
            {
                ErrorBundle msg = createErrorBundle(
                    "SignedMailValidator.noSignedMessage");
                throw new SignedMailValidatorException(msg);
            }

            // save certstore and signerInformationStore
            certs = new JcaCertStoreBuilder().addCertificates(s.getCertificates()).addCRLs(s.getCRLs()).setProvider("BC").build();
            signers = s.getSignerInfos();

            // save "from" addresses from message
            Address[] froms = message.getFrom();
            InternetAddress sender = null;
            try
            {
                if (message.getHeader("Sender") != null)
                {
                    sender = new InternetAddress(message.getHeader("Sender")[0]);
                }
            }
            catch (MessagingException ex)
            {
                //ignore garbage in Sender: header
            }

            int fromsLength = (froms != null) ? froms.length : 0;
            fromAddresses = new String[fromsLength + ((sender != null) ? 1 : 0)];
            for (int i = 0; i < fromsLength; i++)
            {
                InternetAddress inetAddr = (InternetAddress)froms[i];
                fromAddresses[i] = inetAddr.getAddress();
            }
            if (sender != null)
            {
                fromAddresses[fromsLength] = sender.getAddress();
            }

            // initialize results
            results = new HashMap();
        }
        catch (Exception e)
        {
            if (e instanceof SignedMailValidatorException)
            {
                throw (SignedMailValidatorException)e;
            }
            // exception reading message
            ErrorBundle msg = createErrorBundle(
                "SignedMailValidator.exceptionReadingMessage",
                new Object[]{e.getMessage(), e, e.getClass().getName()});
            throw new SignedMailValidatorException(msg, e);
        }

        // validate signatues
        validateSignatures(param);
    }

    protected void validateSignatures(PKIXParameters pkixParam)
    {
        PKIXParameters usedParameters = (PKIXParameters)pkixParam.clone();

        // add crls and certs from mail
        usedParameters.addCertStore(certs);

        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        // check each signer
        while (it.hasNext())
        {
            List errors = new ArrayList();
            List notifications = new ArrayList();

            SignerInformation signer = (SignerInformation)it.next();
            // signer certificate
            X509Certificate cert = null;

            try
            {
                Collection certCollection = findCerts(usedParameters
                    .getCertStores(), selectorConverter.getCertSelector(signer.getSID()));

                Iterator certIt = certCollection.iterator();
                if (certIt.hasNext())
                {
                    cert = (X509Certificate)certIt.next();
                }
            }
            catch (CertStoreException cse)
            {
                ErrorBundle msg = createErrorBundle(
                    "SignedMailValidator.exceptionRetrievingSignerCert",
                    new Object[]{cse.getMessage(), cse, cse.getClass().getName()});
                errors.add(msg);
            }

            if (cert != null)
            {
                // check signature
                boolean validSignature = false;
                try
                {
                    validSignature = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert.getPublicKey()));
                    if (!validSignature)
                    {
                        ErrorBundle msg = createErrorBundle(
                            "SignedMailValidator.signatureNotVerified");
                        errors.add(msg);
                    }
                }
                catch (Exception e)
                {
                    ErrorBundle msg = createErrorBundle(
                        "SignedMailValidator.exceptionVerifyingSignature",
                        new Object[]{e.getMessage(), e, e.getClass().getName()});
                    errors.add(msg);
                }

                // check signer certificate (mail address, key usage, etc)
                checkSignerCert(cert, errors, notifications);

                // notify if a signed receip request is in the message
                AttributeTable atab = signer.getSignedAttributes();
                if (atab != null)
                {
                    Attribute attr = atab.get(PKCSObjectIdentifiers.id_aa_receiptRequest);
                    if (attr != null)
                    {
                        ErrorBundle msg = createErrorBundle(
                            "SignedMailValidator.signedReceiptRequest");
                        notifications.add(msg);
                    }
                }

                // check certificate path

                // get signing time if possible, otherwise use current time as
                // signing time
                Date signTime = getSignatureTime(signer);
                if (signTime == null) // no signing time was found
                {
                    ErrorBundle msg = createErrorBundle(
                        "SignedMailValidator.noSigningTime");
                    notifications.add(msg);
                    signTime = pkixParam.getDate();
                    if (signTime == null)
                    {
                        signTime = new Date();
                    }
                }
                else
                {
                    // check if certificate was valid at signing time
                    try
                    {
                        cert.checkValidity(signTime);
                    }
                    catch (CertificateExpiredException e)
                    {
                        ErrorBundle msg = createErrorBundle(
                            "SignedMailValidator.certExpired",
                            new Object[]{new TrustedInput(signTime), new TrustedInput(cert.getNotAfter())});
                        errors.add(msg);
                    }
                    catch (CertificateNotYetValidException e)
                    {
                        ErrorBundle msg = createErrorBundle(
                            "SignedMailValidator.certNotYetValid",
                            new Object[]{new TrustedInput(signTime), new TrustedInput(cert.getNotBefore())});
                        errors.add(msg);
                    }
                }
                usedParameters.setDate(signTime);

                try
                {
                    // construct cert chain
                    CertPath certPath;
                    List userProvidedList;

                    List userCertStores = new ArrayList();
                    userCertStores.add(certs);
                    Object[] cpres = createCertPath(cert, usedParameters.getTrustAnchors(), pkixParam.getCertStores(), userCertStores);
                    certPath = (CertPath)cpres[0];
                    userProvidedList = (List)cpres[1];

                    // validate cert chain
                    PKIXCertPathReviewer review;
                    try
                    {
                        review = (PKIXCertPathReviewer)certPathReviewerClass.newInstance();
                    }
                    catch (IllegalAccessException e)
                    {
                        throw new IllegalArgumentException("Cannot instantiate object of type " +
                            certPathReviewerClass.getName() + ": " + e.getMessage());
                    }
                    catch (InstantiationException e)
                    {
                        throw new IllegalArgumentException("Cannot instantiate object of type " +
                            certPathReviewerClass.getName() + ": " + e.getMessage());
                    }
                    review.init(certPath, usedParameters);
                    if (!review.isValidCertPath())
                    {
                        ErrorBundle msg = createErrorBundle(
                            "SignedMailValidator.certPathInvalid");
                        errors.add(msg);
                    }
                    results.put(signer, new ValidationResult(review,
                        validSignature, errors, notifications, userProvidedList));
                }
                catch (GeneralSecurityException gse)
                {
                    // cannot create cert path
                    ErrorBundle msg = createErrorBundle(
                        "SignedMailValidator.exceptionCreateCertPath",
                        new Object[]{gse.getMessage(), gse, gse.getClass().getName()});
                    errors.add(msg);
                    results.put(signer, new ValidationResult(null,
                        validSignature, errors, notifications, null));
                }
                catch (CertPathReviewerException cpre)
                {
                    // cannot initialize certpathreviewer - wrong parameters
                    errors.add(cpre.getErrorMessage());
                    results.put(signer, new ValidationResult(null,
                        validSignature, errors, notifications, null));
                }
            }
            else
            // no signer certificate found
            {
                ErrorBundle msg = createErrorBundle(
                    "SignedMailValidator.noSignerCert");
                errors.add(msg);
                results.put(signer, new ValidationResult(null, false, errors,
                    notifications, null));
            }
        }
    }

    public static Set getEmailAddresses(X509Certificate cert)
        throws IOException, CertificateEncodingException
    {
        Set addresses = new HashSet();

        TBSCertificate tbsCertificate = getTBSCert(cert);

        RDN[] rdns = tbsCertificate.getSubject().getRDNs(PKCSObjectIdentifiers.pkcs_9_at_emailAddress);
        for (int i = 0; i < rdns.length; i++)
        {
            AttributeTypeAndValue[] atVs = rdns[i].getTypesAndValues();

            for (int j = 0; j != atVs.length; j++)
            {
                if (atVs[j].getType().equals(PKCSObjectIdentifiers.pkcs_9_at_emailAddress))
                {
                    String email = ((ASN1String)atVs[j].getValue()).getString().toLowerCase();
                    addresses.add(email);
                }
            }
        }

        byte[] ext = cert.getExtensionValue(SUBJECT_ALTERNATIVE_NAME);
        if (ext != null)
        {
            ASN1Sequence altNames = ASN1Sequence.getInstance(getObject(ext));
            for (int j = 0; j < altNames.size(); j++)
            {
                ASN1TaggedObject o = (ASN1TaggedObject)altNames
                    .getObjectAt(j);

                if (o.getTagNo() == 1)
                {
                    String email = DERIA5String.getInstance(o, false)
                        .getString().toLowerCase();
                    addresses.add(email);
                }
            }
        }

        return addresses;
    }

    private static ASN1Primitive getObject(byte[] ext)
        throws IOException
    {
        ASN1InputStream aIn = new ASN1InputStream(ext);
        ASN1OctetString octs = ASN1OctetString.getInstance(aIn.readObject());

        return ASN1Primitive.fromByteArray(octs.getOctets());
    }

    protected void checkSignerCert(X509Certificate cert, List errors,
                                   List notifications)
    {
        // get key length
        PublicKey key = cert.getPublicKey();
        int keyLength = -1;
        if (key instanceof RSAPublicKey)
        {
            keyLength = ((RSAPublicKey)key).getModulus().bitLength();
        }
        else if (key instanceof DSAPublicKey)
        {
            keyLength = ((DSAPublicKey)key).getParams().getP().bitLength();
        }
        if (keyLength != -1 && keyLength <= shortKeyLength)
        {
            ErrorBundle msg = createErrorBundle(
                "SignedMailValidator.shortSigningKey",
                new Object[]{Integers.valueOf(keyLength)});
            notifications.add(msg);
        }

        // warn if certificate has very long validity period
        long validityPeriod = cert.getNotAfter().getTime() - cert.getNotBefore().getTime();
        if (validityPeriod > THIRTY_YEARS_IN_MILLI_SEC)
        {
            ErrorBundle msg = createErrorBundle(
                "SignedMailValidator.longValidity",
                new Object[]{new TrustedInput(cert.getNotBefore()), new TrustedInput(cert.getNotAfter())});
            notifications.add(msg);
        }

        // check key usage if digitalSignature or nonRepudiation is set
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage != null && !keyUsage[0] && !keyUsage[1])
        {
            ErrorBundle msg = createErrorBundle(
                "SignedMailValidator.signingNotPermitted");
            errors.add(msg);
        }

        // check extended key usage
        try
        {
            byte[] ext = cert.getExtensionValue(EXT_KEY_USAGE);
            if (ext != null)
            {
                ExtendedKeyUsage extKeyUsage = ExtendedKeyUsage
                    .getInstance(getObject(ext));
                if (!extKeyUsage
                    .hasKeyPurposeId(KeyPurposeId.anyExtendedKeyUsage)
                    && !extKeyUsage
                    .hasKeyPurposeId(KeyPurposeId.id_kp_emailProtection))
                {
                    ErrorBundle msg = createErrorBundle(
                        "SignedMailValidator.extKeyUsageNotPermitted");
                    errors.add(msg);
                }
            }
        }
        catch (Exception e)
        {
            ErrorBundle msg = createErrorBundle(
                "SignedMailValidator.extKeyUsageError", new Object[]{
                e.getMessage(), e, e.getClass().getName()}
            );
            errors.add(msg);
        }

        // cert has an email address
        try
        {
            Set certEmails = getEmailAddresses(cert);
            if (certEmails.isEmpty())
            {
                // error no email address in signing certificate
                ErrorBundle msg = createErrorBundle(
                    "SignedMailValidator.noEmailInCert");
                errors.add(msg);
            }
            else
            {
                // check if email in cert is equal to the from address in the
                // message
                boolean equalsFrom = false;
                for (int i = 0; i < fromAddresses.length; i++)
                {
                    if (certEmails.contains(fromAddresses[i].toLowerCase()))
                    {
                        equalsFrom = true;
                        break;
                    }
                }
                if (!equalsFrom)
                {
                    ErrorBundle msg = createErrorBundle(
                        "SignedMailValidator.emailFromCertMismatch",
                        new Object[]{
                            new UntrustedInput(
                                addressesToString(fromAddresses)),
                            new UntrustedInput(certEmails)}
                    );
                    errors.add(msg);
                }
            }
        }
        catch (Exception e)
        {
            ErrorBundle msg = createErrorBundle(
                "SignedMailValidator.certGetEmailError", new Object[]{
                e.getMessage(), e, e.getClass().getName()}
            );
            errors.add(msg);
        }
    }

    static String addressesToString(Object[] a)
    {
        if (a == null)
        {
            return "null";
        }

        StringBuffer b = new StringBuffer();
        b.append('[');

        for (int i = 0; i != a.length; i++)
        {
            if (i > 0)
            {
                b.append(", ");
            }
            b.append(String.valueOf(a[i]));
        }

        return b.append(']').toString();
    }

    public static Date getSignatureTime(SignerInformation signer)
    {
        AttributeTable atab = signer.getSignedAttributes();
        Date result = null;
        if (atab != null)
        {
            Attribute attr = atab.get(CMSAttributes.signingTime);
            if (attr != null)
            {
                Time t = Time.getInstance(attr.getAttrValues().getObjectAt(0)
                    .toASN1Primitive());
                result = t.getDate();
            }
        }
        return result;
    }

    private static List findCerts(List certStores, X509CertSelector selector)
        throws CertStoreException
    {
        List result = new ArrayList();
        Iterator it = certStores.iterator();
        while (it.hasNext())
        {
            CertStore store = (CertStore)it.next();
            Collection coll = store.getCertificates(selector);
            // sometimes the subjectKeyIdentifier in a TA certificate, even when the authorityKeyIdentifier is set.
            // where this happens we role back to a simpler match to make sure we've got all the possibilities.
            if (coll.isEmpty() && selector.getSubjectKeyIdentifier() != null)
            {
                X509CertSelector certSelector = (X509CertSelector)selector.clone();
                certSelector.setSubjectKeyIdentifier(null);
                coll = store.getCertificates(certSelector);
            }
            result.addAll(coll);
        }
        return result;
    }

    private static X509Certificate findNextCert(List certStores, X509CertSelector selector, Set certSet)
        throws CertStoreException
    {
        Iterator certIt = findCerts(certStores, selector).iterator();

        boolean certFound = false;
        X509Certificate nextCert = null;
        while (certIt.hasNext())
        {
            nextCert = (X509Certificate)certIt.next();
            if (!certSet.contains(nextCert))
            {
                certFound = true;
                break;
            }
        }

        return certFound ? nextCert : null;
    }

    /**
     * @param signerCert   the end of the path
     * @param trustanchors trust anchors for the path
     * @param certStores
     * @return the resulting certificate path.
     * @throws GeneralSecurityException
     */
    public static CertPath createCertPath(X509Certificate signerCert,
                                          Set trustanchors, List certStores)
        throws GeneralSecurityException
    {
        Object[] results = createCertPath(signerCert, trustanchors, certStores, null);
        return (CertPath)results[0];
    }

    /**
     * Returns an Object array containing a CertPath and a List of Booleans. The list contains the value <code>true</code>
     * if the corresponding certificate in the CertPath was taken from the user provided CertStores.
     *
     * @param signerCert       the end of the path
     * @param trustanchors     trust anchors for the path
     * @param systemCertStores list of {@link CertStore} provided by the system
     * @param userCertStores   list of {@link CertStore} provided by the user
     * @return a CertPath and a List of booleans.
     * @throws GeneralSecurityException
     */
    public static Object[] createCertPath(X509Certificate signerCert,
                                          Set trustanchors, List systemCertStores, List userCertStores)
        throws GeneralSecurityException
    {
        Set certSet = new LinkedHashSet();
        List userProvidedList = new ArrayList();

        // add signer certificate

        X509Certificate cert = signerCert;
        certSet.add(cert);
        userProvidedList.add(new Boolean(true));

        boolean trustAnchorFound = false;

        X509Certificate taCert = null;

        // add other certs to the cert path
        while (cert != null && !trustAnchorFound)
        {
            // check if cert Issuer is Trustanchor
            Iterator trustIt = trustanchors.iterator();
            while (trustIt.hasNext())
            {
                TrustAnchor anchor = (TrustAnchor)trustIt.next();
                X509Certificate anchorCert = anchor.getTrustedCert();
                if (anchorCert != null)
                {
                    if (anchorCert.getSubjectX500Principal().equals(
                        cert.getIssuerX500Principal()))
                    {
                        try
                        {
                            cert.verify(anchorCert.getPublicKey(), "BC");
                            trustAnchorFound = true;
                            taCert = anchorCert;
                            break;
                        }
                        catch (Exception e)
                        {
                            // trustanchor not found
                        }
                    }
                }
                else
                {
                    if (anchor.getCAName().equals(
                        cert.getIssuerX500Principal().getName()))
                    {
                        try
                        {
                            cert.verify(anchor.getCAPublicKey(), "BC");
                            trustAnchorFound = true;
                            break;
                        }
                        catch (Exception e)
                        {
                            // trustanchor not found
                        }
                    }
                }
            }

            if (!trustAnchorFound)
            {
                // add next cert to path
                X509CertSelector select = new X509CertSelector();
                try
                {
                    select.setSubject(cert.getIssuerX500Principal().getEncoded());
                }
                catch (IOException e)
                {
                    throw new IllegalStateException(e.toString());
                }
                byte[] authKeyIdentBytes = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
                if (authKeyIdentBytes != null)
                {
                    try
                    {
                        AuthorityKeyIdentifier kid = AuthorityKeyIdentifier.getInstance(getObject(authKeyIdentBytes));
                        if (kid.getKeyIdentifier() != null)
                        {
                            select.setSubjectKeyIdentifier(new DEROctetString(kid.getKeyIdentifier()).getEncoded(ASN1Encoding.DER));
                        }
                    }
                    catch (IOException ioe)
                    {
                        // ignore
                    }
                }
                boolean userProvided = false;

                cert = findNextCert(systemCertStores, select, certSet);
                if (cert == null && userCertStores != null)
                {
                    userProvided = true;
                    cert = findNextCert(userCertStores, select, certSet);
                }

                if (cert != null)
                {
                    // cert found
                    certSet.add(cert);
                    userProvidedList.add(new Boolean(userProvided));
                }
            }
        }

        // if a trustanchor was found - try to find a selfsigned certificate of
        // the trustanchor
        if (trustAnchorFound)
        {
            if (taCert != null && taCert.getSubjectX500Principal().equals(taCert.getIssuerX500Principal()))
            {
                certSet.add(taCert);
                userProvidedList.add(new Boolean(false));
            }
            else
            {
                X509CertSelector select = new X509CertSelector();

                try
                {
                    select.setSubject(cert.getIssuerX500Principal().getEncoded());
                    select.setIssuer(cert.getIssuerX500Principal().getEncoded());
                }
                catch (IOException e)
                {
                    throw new IllegalStateException(e.toString());
                }

                boolean userProvided = false;

                taCert = findNextCert(systemCertStores, select, certSet);
                if (taCert == null && userCertStores != null)
                {
                    userProvided = true;
                    taCert = findNextCert(userCertStores, select, certSet);
                }
                if (taCert != null)
                {
                    try
                    {
                        cert.verify(taCert.getPublicKey(), "BC");
                        certSet.add(taCert);
                        userProvidedList.add(new Boolean(userProvided));
                    }
                    catch (GeneralSecurityException gse)
                    {
                        // wrong cert
                    }
                }
            }
        }

        CertPath certPath = CertificateFactory.getInstance("X.509", "BC").generateCertPath(new ArrayList(certSet));
        return new Object[]{certPath, userProvidedList};
    }

    public CertStore getCertsAndCRLs()
    {
        return certs;
    }

    public SignerInformationStore getSignerInformationStore()
    {
        return signers;
    }

    public ValidationResult getValidationResult(SignerInformation signer)
        throws SignedMailValidatorException
    {
        if (signers.getSigners(signer.getSID()).isEmpty())
        {
            // the signer is not part of the SignerInformationStore
            // he has not signed the message
            ErrorBundle msg = createErrorBundle(
                "SignedMailValidator.wrongSigner");
            throw new SignedMailValidatorException(msg);
        }
        else
        {
            return (ValidationResult)results.get(signer);
        }
    }

    public static class ValidationResult
    {

        private PKIXCertPathReviewer review;

        private List errors;

        private List notifications;

        private List userProvidedCerts;

        private boolean signVerified;

        ValidationResult(PKIXCertPathReviewer review, boolean verified,
                         List errors, List notifications, List userProvidedCerts)
        {
            this.review = review;
            this.errors = errors;
            this.notifications = notifications;
            this.signVerified = verified;
            this.userProvidedCerts = userProvidedCerts;
        }

        /**
         * Returns a list of error messages of type {@link ErrorBundle}.
         *
         * @return List of error messages
         */
        public List getErrors()
        {
            return errors;
        }

        /**
         * Returns a list of notification messages of type {@link ErrorBundle}.
         *
         * @return List of notification messages
         */
        public List getNotifications()
        {
            return notifications;
        }

        /**
         * @return the PKIXCertPathReviewer for the CertPath of this signature
         * or null if an Exception occurred.
         */
        public PKIXCertPathReviewer getCertPathReview()
        {
            return review;
        }

        /**
         * @return the CertPath for this signature
         * or null if an Exception occurred.
         */
        public CertPath getCertPath()
        {
            return review != null ? review.getCertPath() : null;
        }

        /**
         * @return a List of Booleans that are true if the corresponding certificate in the CertPath was taken from
         * the CertStore of the SMIME message
         */
        public List getUserProvidedCerts()
        {
            return userProvidedCerts;
        }

        /**
         * @return true if the signature corresponds to the public key of the
         * signer
         */
        public boolean isVerifiedSignature()
        {
            return signVerified;
        }

        /**
         * @return true if the signature is valid (ie. if it corresponds to the
         * public key of the signer and the cert path for the signers
         * certificate is also valid)
         */
        public boolean isValidSignature()
        {
            if (review != null)
            {
                return signVerified && review.isValidCertPath() && errors.isEmpty();
            }
            else
            {
                return false;
            }
        }
    }

    private static TBSCertificate getTBSCert(X509Certificate cert)
        throws CertificateEncodingException
    {
        return TBSCertificate.getInstance(cert.getTBSCertificate());
    }
    
    private static ErrorBundle createErrorBundle(String id)
    {
        ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, id);
        msg.setClassLoader(SignedMailValidator.class.getClassLoader());
        
        return msg;
    }
    
    private static ErrorBundle createErrorBundle(String id, Object[] arguments)
    {
        ErrorBundle msg = new ErrorBundle(RESOURCE_NAME, id, arguments);
        msg.setClassLoader(SignedMailValidator.class.getClassLoader());
        
        return msg;
    }
}
