package org.nick.nfcsmime;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.operator.ContentSigner;

public class MuscleCardContentSigner implements ContentSigner {

    private ByteArrayOutputStream baos = new ByteArrayOutputStream();
    private MuscleCard msc;
    private String pin;

    public MuscleCardContentSigner(MuscleCard msc, String pin) {
        this.msc = msc;
        this.pin = pin;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return AlgorithmIdentifier
                .getInstance(PKCSObjectIdentifiers.sha512WithRSAEncryption);
    }

    @Override
    public OutputStream getOutputStream() {
        return baos;
    }

    @Override
    public byte[] getSignature() {
        try {
            msc.select();
            boolean pinValid = msc.verifyPin(pin);
            if (!pinValid) {
                throw new IllegalStateException("Invalid PIN");
            }

            byte[] data = baos.toByteArray();
            baos.reset();
            return msc.sign(data);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
