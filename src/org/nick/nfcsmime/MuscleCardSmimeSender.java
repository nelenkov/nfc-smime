package org.nick.nfcsmime;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Properties;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.cms.SignerInfoGenerator;
import org.spongycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class MuscleCardSmimeSender extends SmimeSender {

    private MuscleCard msc;
    private X509Certificate signerCert;
    private String pin;

    public MuscleCardSmimeSender(Properties sessionProps, String userName,
            String password, MuscleCard msc, String pin) {
        super(sessionProps, userName, password);
        this.msc = msc;
        this.pin = pin;
    }

    @Override
    public X509Certificate getSignerCertificate() {
        try {
            if (signerCert == null) {
                byte[] certBytes;

                msc.select();
                certBytes = msc.readSignerCertificate();

                CertificateFactory cf = CertificateFactory.getInstance("X509");
                signerCert = (X509Certificate) cf
                        .generateCertificate(new ByteArrayInputStream(certBytes));
            }

            return signerCert;
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected SignerInfoGenerator createSignerInfoGenerator(
            ASN1EncodableVector signedAttrs) {
        try {
            if (msc == null) {
                throw new IllegalStateException("NFC card not found");
            }

            msc.select();
            MuscleCardContentSigner mscCs = new MuscleCardContentSigner(msc,
                    pin);

            return new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider("SC")
                            .build()).build(mscCs, getSignerCertificate());
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
    }
}
