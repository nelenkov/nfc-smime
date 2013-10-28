package org.nick.nfcsmime;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Properties;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Environment;
import android.os.StrictMode;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity implements OnClickListener {

    private static final int PKCS12_IMPORT_REQUEST_CODE = 42;

    private static final String MUSCLE_PIN = "00000000";

    private static final String TAG = MainActivity.class.getSimpleName();

    private static final String PKCS12_FILENAME = "smime-gmail.p12";
    private static final String SMIME_CERT_ALIAS = "smime-gmail";

    private static final String GMAIL_PASSWORD = "";
    private static final String GMAIL_ACCOUNT = "";

    private static final String DEFAULT_RECIPIENT = "";

    private static final boolean DEBUG_SMTP = false;

    static {
        Security.insertProviderAt(
                new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    private NfcAdapter adapter;
    private PendingIntent pendingIntent;
    private IntentFilter[] filters;
    private String[][] techLists;

    private TextView fromText;
    private EditText toText;
    private EditText subjectText;
    private EditText bodyText;
    private TextView messageText;
    private Button importPkcs12Button;
    private Button sendMailButton;
    private Button nfcSignButton;

    private X509Certificate caCert;
    private X509Certificate signerCert;
    private KeyPair signerKeyPair;

    private MuscleCard msc;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.LAX);

        requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        fromText = (TextView) findViewById(R.id.from_text);
        toText = (EditText) findViewById(R.id.to_text);
        toText.setText(DEFAULT_RECIPIENT);
        subjectText = (EditText) findViewById(R.id.subject_text);
        bodyText = (EditText) findViewById(R.id.body_text);
        messageText = (TextView) findViewById(R.id.message);

        sendMailButton = (Button) findViewById(R.id.send_mail_button);
        sendMailButton.setOnClickListener(this);
        importPkcs12Button = (Button) findViewById(R.id.import_pkcs12_button);
        importPkcs12Button.setOnClickListener(this);
        nfcSignButton = (Button) findViewById(R.id.send_mail_nfc_button);
        nfcSignButton.setOnClickListener(this);
        nfcSignButton.setEnabled(false);

        adapter = NfcAdapter.getDefaultAdapter(this);

        pendingIntent = PendingIntent.getActivity(this, 0, new Intent(this,
                getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);

        IntentFilter techDiscovered = new IntentFilter(
                NfcAdapter.ACTION_TECH_DISCOVERED);
        filters = new IntentFilter[] { techDiscovered };
        techLists = new String[][] { new String[] { IsoDep.class.getName() } };

        tryLoadFromKeyStore();
    }

    @Override
    public void onPause() {
        super.onPause();
        if (adapter != null) {
            adapter.disableForegroundDispatch(this);
        }
    }

    @Override
    public void onResume() {
        super.onResume();

        if (adapter != null) {
            adapter.enableForegroundDispatch(this, pendingIntent, filters,
                    techLists);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        Log.d(TAG, "Intent: " + intent);

        setIntent(intent);

        try {
            if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent.getAction())
                    || NfcAdapter.ACTION_TAG_DISCOVERED.equals(intent
                            .getAction())) {
                Tag tagFromIntent = intent
                        .getParcelableExtra(NfcAdapter.EXTRA_TAG);
                messageText.setText("Found NFC tag: ");
                Log.d(TAG, "Suported techs: ");
                for (String tech : tagFromIntent.getTechList()) {
                    Log.d(TAG, "\t" + tech);
                    messageText.append(tech.replaceAll("android.nfc.", "")
                            + " ");
                }
                messageText.append("\n");

                IsoDep tag = IsoDep.get(tagFromIntent);
                if (tag == null) {
                    Log.w(TAG, "Not an IsoDep tag: " + tagFromIntent);
                    return;
                }

                tag.connect();
                msc = new MuscleCard(tag);

                try {
                    msc.select();

                    messageText.append("Found MuscleCard");
                    nfcSignButton.setEnabled(true);
                } finally {
                    if (tag != null) {
                        tag.close();
                    }
                }

            }
        } catch (Exception e) {
            Log.e(TAG, "Error: " + e.getMessage(), e);
            Toast.makeText(this, "Error: " + e.getMessage(), Toast.LENGTH_LONG)
                    .show();
        }
    }

    private void sendMail(boolean signWithCard) throws Exception {
        if (!signWithCard && (signerCert == null || caCert == null)) {
            throw new IllegalStateException("Load signing certificate first");
        }

        final SmimeSender sender = createSender(signWithCard);
        final String fromAddress = sender.getSignerRfc822Name();
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                fromText.setText(fromAddress);
            }
        });

        sender.sendMail(fromAddress, toText.getText().toString(), subjectText
                .getText().toString(), bodyText.getText().toString());
    }

    private SmimeSender createSender(boolean signWithCard) {
        if (signWithCard) {
            return new MuscleCardSmimeSender(createGmailProps(), GMAIL_ACCOUNT,
                    GMAIL_PASSWORD, msc, MUSCLE_PIN);
        }

        return new LocalKeySmimeSender(createGmailProps(), GMAIL_ACCOUNT,
                GMAIL_PASSWORD, signerCert, signerKeyPair.getPrivate());
    }

    private Properties createGmailProps() {
        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.gmail.com");

        props.put("mail.debug", DEBUG_SMTP);
        props.put("mail.smtp.auth", "true");

        props.put("mail.smtp.port", "465");
        props.put("mail.smtp.socketFactory.port", "465");
        props.put("mail.smtp.socketFactory.class",
                "javax.net.ssl.SSLSocketFactory");
        props.put("mail.smtp.socketFactory.fallback", "false");

        return props;
    }

    @Override
    public void onClick(final View v) {
        new AsyncTask<Void, Void, Void>() {

            Exception error;

            boolean importPkcs12Enabled;
            boolean sendMailEnabled;
            boolean nfcSignEnabled;

            @Override
            public void onPreExecute() {
                setProgressBarIndeterminateVisibility(true);
                disableButtons();
                switch (v.getId()) {
                case R.id.import_pkcs12_button:
                    messageText.setText("Importing PKCS#12 file...");
                    break;
                case R.id.send_mail_button:
                case R.id.send_mail_nfc_button:
                    messageText.setText("Sending signed email...");
                    break;
                }
            }

            @Override
            protected Void doInBackground(Void... arg0) {
                try {
                    switch (v.getId()) {
                    case R.id.import_pkcs12_button:
                        final byte[] p12 = readFile(PKCS12_FILENAME);

                        runOnUiThread(new Runnable() {
                            public void run() {
                                Intent intent = KeyChain.createInstallIntent();
                                intent.putExtra(KeyChain.EXTRA_PKCS12, p12);
                                intent.putExtra(KeyChain.EXTRA_NAME,
                                        SMIME_CERT_ALIAS);
                                startActivityForResult(intent, 42);
                            }
                        });
                        break;
                    case R.id.send_mail_button:
                        sendMail(false);
                        break;
                    case R.id.send_mail_nfc_button:
                        sendMail(true);
                        break;
                    }
                } catch (Exception e) {
                    Log.e(TAG, "Error sending mail: " + e.getMessage(), e);
                    error = e;
                }

                return null;
            }

            private void disableButtons() {
                importPkcs12Enabled = importPkcs12Button.isEnabled();
                sendMailEnabled = sendMailButton.isEnabled();
                nfcSignEnabled = nfcSignButton.isEnabled();

                importPkcs12Button.setEnabled(false);
                sendMailButton.setEnabled(false);
                nfcSignButton.setEnabled(false);
            }

            private void enableButtons() {
                importPkcs12Button.setEnabled(importPkcs12Enabled);
                sendMailButton.setEnabled(sendMailEnabled);
                nfcSignButton.setEnabled(nfcSignEnabled);
            }

            public void onPostExecute(Void result) {
                setProgressBarIndeterminateVisibility(false);
                enableButtons();
                messageText.setText("");

                if (error != null) {
                    Toast.makeText(MainActivity.this,
                            "Error sending mail: " + error.getMessage(),
                            Toast.LENGTH_LONG).show();
                }
            }
        }.execute();
    }

    private void loadCertificateFromKeyStore() {
        KeyChain.choosePrivateKeyAlias(MainActivity.this,
                new KeyChainAliasCallback() {

                    @Override
                    public void alias(String alias) {
                        try {
                            PrivateKey privKey = KeyChain.getPrivateKey(
                                    MainActivity.this, SMIME_CERT_ALIAS);
                            X509Certificate[] chain = KeyChain
                                    .getCertificateChain(MainActivity.this,
                                            SMIME_CERT_ALIAS);
                            if (privKey == null || chain == null
                                    || chain.length == 0) {
                                throw new IllegalStateException(
                                        "SMIME certificate not found, import PKCS#12 file first.");
                            }
                            RSAPublicKey pubKey = (RSAPublicKey) chain[0]
                                    .getPublicKey();
                            signerKeyPair = new KeyPair(pubKey, privKey);
                            signerCert = (X509Certificate) chain[0];
                            caCert = chain[1];
                        } catch (KeyChainException e) {
                            throw new RuntimeException(e);
                        } catch (InterruptedException e) {
                            Log.e(TAG, "Interrupted?: " + e.getMessage(), e);
                        }
                    }
                }, new String[] { "RSA" }, null, null, 0, SMIME_CERT_ALIAS);
    }

    private void tryLoadFromKeyStore() {
        new AsyncTask<Void, Void, Void>() {

            @Override
            public void onPreExecute() {
                setProgressBarIndeterminateVisibility(true);
            }

            @Override
            protected Void doInBackground(Void... arg0) {
                try {
                    PrivateKey privKey = KeyChain.getPrivateKey(
                            MainActivity.this, SMIME_CERT_ALIAS);
                    X509Certificate[] chain = KeyChain.getCertificateChain(
                            MainActivity.this, SMIME_CERT_ALIAS);
                    if (privKey != null && chain != null && chain.length > 1) {
                        RSAPublicKey pubKey = (RSAPublicKey) chain[0]
                                .getPublicKey();
                        signerKeyPair = new KeyPair(pubKey, privKey);
                        signerCert = chain[0];
                        caCert = chain[1];
                    }
                } catch (Exception e) {
                    Log.e(TAG, "Error loading key: " + e.getMessage(), e);
                }

                return null;
            }

            @Override
            public void onPostExecute(Void result) {
                setProgressBarIndeterminateVisibility(false);
                if (signerCert != null && signerKeyPair != null) {
                    importPkcs12Button.setEnabled(false);
                }
            }
        }.execute();
    }

    private static byte[] readFile(String filename) throws Exception {
        File f = new File(Environment.getExternalStorageDirectory(), filename);
        byte[] result = new byte[(int) f.length()];
        FileInputStream in = new FileInputStream(f);
        in.read(result);
        in.close();

        return result;
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == RESULT_OK & requestCode == PKCS12_IMPORT_REQUEST_CODE) {
            loadCertificateFromKeyStore();
        }
    }

}
