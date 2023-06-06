package org.bouncycastle.openpgp.examples;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;
import javax.swing.filechooser.FileSystemView;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

/**
 * A simple utility class that generates a RSA PGPPublicKey/PGPSecretKey pair.
 * <p>
 * usage: RSAKeyPairGenerator [-a] identity passPhrase
 * <p>
 * Where identity is the name to be associated with the public key. The keys are
 * placed in the files pub.[asc|bpg] and secret.[asc|bpg].
 */
public class RSAKeyPairGenerator {

    private static void exportKeyPair(
            OutputStream secretOut,
            OutputStream publicOut,
            KeyPair pair,
            String identity,
            char[] passPhrase,
            boolean armor)
            throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException {
        if (armor) {
            secretOut = new ArmoredOutputStream(secretOut);
        }

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyPair keyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, pair, new Date());
        PGPSecretKey secretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION, keyPair, identity, sha1Calc, null, null, new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase));

        secretKey.encode(secretOut);

        secretOut.close();

        if (armor) {
            publicOut = new ArmoredOutputStream(publicOut);
        }

        PGPPublicKey key = secretKey.getPublicKey();

        key.encode(publicOut);

        publicOut.close();
    }

    public static void main(
            String[] args)
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", "BC");

        kpg.initialize(2048);

        KeyPair kp = kpg.generateKeyPair();

        String[] arg = {"-a", "stic<hej@gmail.com>", "krc"};
        
        

        if (arg.length < 2) {
            System.out.println("RSAKeyPairGenerator [-a] identity passPhrase");
            System.exit(0);
        }

        if (arg[0].equals("-a")) {
            if (arg.length < 3) {
                System.out.println("RSAKeyPairGenerator [-a] identity passPhrase");
                System.exit(0);
            }

            FileOutputStream out1 = new FileOutputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//secret.asc");
            FileOutputStream out2 = new FileOutputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//pub.asc");

            exportKeyPair(out1, out2, kp, arg[1], arg[2].toCharArray(), true);

            System.out.println("Keys are generated!");
        } else {
            FileOutputStream out1 = new FileOutputStream("secret.bpg");
            FileOutputStream out2 = new FileOutputStream("pub.bpg");

            exportKeyPair(out1, out2, kp, arg[0], arg[1].toCharArray(), false);
        }
    }
}
