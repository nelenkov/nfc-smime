package org.nick.nfcsmime;

import java.io.File;
import java.io.FileOutputStream;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import javax.mail.Address;
import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.cms.IssuerAndSerialNumber;
import org.spongycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.spongycastle.asn1.smime.SMIMECapability;
import org.spongycastle.asn1.smime.SMIMECapabilityVector;
import org.spongycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.cert.jcajce.JcaCertStore;
import org.spongycastle.cms.SignerInfoGenerator;
import org.spongycastle.mail.smime.SMIMESignedGenerator;
import org.spongycastle.util.Store;
import org.spongycastle.x509.extension.X509ExtensionUtil;

import android.os.Environment;

public abstract class SmimeSender {

    private Properties sessionProps;
    private String userName;
    private String password;
    private Authenticator authenticator;

    public SmimeSender(Properties sessionProps, String userName, String password) {
        this.sessionProps = sessionProps;
        this.userName = userName;
        this.password = password;
        if (userName != null && password != null) {
            authenticator = new Authenticator() {
                @Override
                public PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(
                            SmimeSender.this.userName,
                            SmimeSender.this.password);
                }
            };
        }
    }

    public void sendMail(String from, String to, String subject, String body)
            throws Exception {
        X509Certificate signerCert = getSignerCertificate();
        if (signerCert == null) {
            throw new IllegalStateException(
                    "Load signing certificate and key first.");
        }

        ASN1EncodableVector signedAttrs = new ASN1EncodableVector();
        SMIMECapabilityVector caps = new SMIMECapabilityVector();

        caps.addCapability(SMIMECapability.aES256_CBC);
        caps.addCapability(SMIMECapability.dES_EDE3_CBC);
        caps.addCapability(SMIMECapability.dES_CBC);

        signedAttrs.add(new SMIMECapabilitiesAttribute(caps));

        // for encrypted responses
        IssuerAndSerialNumber issAndSer = new IssuerAndSerialNumber(
                new X500Name(signerCert.getSubjectDN().getName()),
                signerCert.getSerialNumber());
        signedAttrs.add(new SMIMEEncryptionKeyPreferenceAttribute(issAndSer));

        SMIMESignedGenerator gen = new SMIMESignedGenerator();
        gen.addSignerInfoGenerator(createSignerInfoGenerator(signedAttrs));

        Store certs = new JcaCertStore(Arrays.asList(signerCert));
        gen.addCertificates(certs);

        Session session = Session.getInstance(sessionProps, authenticator);

        Address fromUser = new InternetAddress(from);
        Address toUser = new InternetAddress(to);

        MimeMessage mimeMsg = new MimeMessage(session);
        mimeMsg.setFrom(fromUser);
        mimeMsg.setRecipient(Message.RecipientType.TO, toUser);
        mimeMsg.setSubject(subject);
        mimeMsg.setContent(body, "text/plain");
        mimeMsg.saveChanges();

        MimeMultipart mm = gen.generate(mimeMsg, "SC");
        MimeMessage signedMessage = new MimeMessage(session);
        Enumeration<?> headers = mimeMsg.getAllHeaderLines();
        while (headers.hasMoreElements()) {
            signedMessage.addHeaderLine((String) headers.nextElement());
        }
        signedMessage.setContent(mm);
        signedMessage.saveChanges();
        signedMessage.writeTo(new FileOutputStream(new File(Environment
                .getExternalStorageDirectory(), "signed.message")));

        Transport.send(signedMessage);
    }

    public abstract X509Certificate getSignerCertificate();

    protected abstract SignerInfoGenerator createSignerInfoGenerator(
            ASN1EncodableVector signedAttrs);

    public String getSignerRfc822Name() {
        return getRfc822Name(getSignerCertificate());
    }

    @SuppressWarnings("rawtypes")
    private static String getRfc822Name(X509Certificate cert) {
        try {
            String rfc822Name = null;
            Collection sans = X509ExtensionUtil
                    .getSubjectAlternativeNames(cert);
            for (Object san : sans) {
                // tag, value
                List list = (List) san;
                if (list.get(1) instanceof String) {
                    rfc822Name = (String) list.get(1);
                    break;
                }
            }

            return rfc822Name;
        } catch (CertificateParsingException e) {
            throw new RuntimeException(e);
        }
    }
}
