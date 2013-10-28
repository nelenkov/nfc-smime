package org.nick.nfcsmime;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Properties;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.cms.AttributeTable;
import org.spongycastle.cms.SignerInfoGenerator;
import org.spongycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.spongycastle.operator.OperatorCreationException;

public class LocalKeySmimeSender extends SmimeSender {

    private X509Certificate signerCert;
    private PrivateKey signerPrivateKey;

    public LocalKeySmimeSender(Properties sessionProps, String userName,
            String password, X509Certificate signerCert,
            PrivateKey signerPrivateKey) {
        super(sessionProps, userName, password);
        this.signerCert = signerCert;
        this.signerPrivateKey = signerPrivateKey;
    }

    @Override
    public X509Certificate getSignerCertificate() {
        return signerCert;
    }

    @Override
    protected SignerInfoGenerator createSignerInfoGenerator(
            ASN1EncodableVector signedAttrs) {
        try {
            return new JcaSimpleSignerInfoGeneratorBuilder()
                    .setProvider("AndroidOpenSSL")
                    .setSignedAttributeGenerator(
                            new AttributeTable(signedAttrs))
                    .build("SHA512withRSA", signerPrivateKey, signerCert);
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
    }
}
