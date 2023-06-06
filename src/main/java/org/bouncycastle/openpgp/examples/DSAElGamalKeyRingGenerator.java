package org.bouncycastle.openpgp.examples;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;
import java.util.zip.Checksum;

import javax.crypto.spec.DHParameterSpec;
import javax.swing.filechooser.FileSystemView;
import javax.xml.crypto.dsig.keyinfo.KeyValue;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CRC24;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import zp2020.UtilHex;

/**
 * A simple utility class that generates a public/secret keyring containing a
 * DSA signing key and an El Gamal key for encryption.
 * <p>
 * usage: DSAElGamalKeyRingGenerator [-a] identity passPhrase
 * <p>
 * Where identity is the name to be associated with the public key. The keys are
 * placed in the files pub.[asc|bpg] and secret.[asc|bpg].
 * <p>
 * <b>Note</b>: this example encrypts the secret key using AES_256, many PGP
 * products still do not support this, if you are having problems importing keys
 * try changing the algorithm id to PGPEncryptedData.CAST5. CAST5 is more widely
 * supported.
 */
public class DSAElGamalKeyRingGenerator {

    private static void exportKeyPair(
            OutputStream secretOut,
            OutputStream publicOut,
            KeyPair dsaKp,
            KeyPair elgKp,
            String identity,
            char[] passPhrase,
            boolean armor)
            throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException, NoSuchAlgorithmException {
        if (armor) {
            secretOut = new ArmoredOutputStream(secretOut);
        }

        
        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());
        PGPKeyPair elgKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date());
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
                identity, sha1Calc, null, null, new JcaPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase));

        keyRingGen.addSubKey(elgKeyPair);

       
        
        
        
        //keyRingGen.generateSecretKeyRing().encode(secretOut);

        //System.out.println("Public Key: algorithm-> " + dsaKeyPair.getPublicKey().getAlgorithm() + " bit strength-> " + dsaKeyPair.getPublicKey().getBitStrength() + " creation time-> " + dsaKeyPair.getPublicKey().getCreationTime() + " fingerprint-> " + UtilHex.toHex(dsaKeyPair.getPublicKey().getFingerprint()) + " key id-> " + dsaKeyPair.getPublicKey().getKeyID() + " key len-> " + UtilHex.toHex(dsaKeyPair.getPublicKey().getEncoded()).length() + " ");
        //secretOut.close();

        if (armor) {
            publicOut = new ArmoredOutputStream(publicOut);
        }

        keyRingGen.generatePublicKeyRing().encode(publicOut);
        //Iterator<PGPPublicKey> it = keyRingGen.generatePublicKeyRing().iterator();
        /*while (it.hasNext()) {
            PGPPublicKey pk = it.next();
            System.out.println("key public: " + UtilHex.toHex(pk.getFingerprint()) + " " + pk.getAlgorithm() + " " + UtilHex.toHex(pk.getEncoded()).length());
        }
         */
        publicOut.close();
    }

    public static void main(
            String[] args)
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String[] arg = {"-a", "sticko_najsladji<sticko@gmail.com>", "krcevi"};
        if (arg.length < 2) {
            System.out.println("DSAElGamalKeyRingGenerator [-a] identity passPhrase");
            System.exit(0);
        }

        
        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");

        dsaKpg.initialize(2048);

        /* System.out.println("private dsa: " + UtilHex.toHex(dsaKpg.genKeyPair().getPrivate().getEncoded()) + ", len: " + UtilHex.toHex(dsaKpg.genKeyPair().getPrivate().getEncoded()).length());
        System.out.println("public dsa: " + UtilHex.toHex(dsaKpg.genKeyPair().getPublic().getEncoded()) + ", len: " + UtilHex.toHex(dsaKpg.genKeyPair().getPublic().getEncoded()).length());*/
        //
        // this takes a while as the key generator has to generate some DSA params
        // before it generates the key.
        //
        KeyPair dsaKp = dsaKpg.generateKeyPair();
        //System.out.println("dsa pub " + UtilHex.toHex(dsaKp.getPublic().getEncoded()) + "\n len " + UtilHex.toHex(dsaKp.getPublic().getEncoded()).length());
        //System.out.println("dsa prv " + UtilHex.toHex(dsaKp.getPrivate().getEncoded()) + "\n len " + UtilHex.toHex(dsaKp.getPrivate().getEncoded()).length());

        KeyPairGenerator elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        BigInteger g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        BigInteger p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

        DHParameterSpec elParams = new DHParameterSpec(p, g);
        

        
        KeyPairGenerator kg = KeyPairGenerator.getInstance("DSA");
        
        //KeyPair k = new 
        //elgKpg.initialize(elParams);
//        elgKpg.initialize(2048);

        //
        // this is quicker because we are using pregenerated parameters.
        //
        KeyPair elgKp = elgKpg.generateKeyPair();

        if (arg[0].equals("-a")) {
            if (arg.length < 3) {
                System.out.println("DSAElGamalKeyRingGenerator [-a] identity passPhrase");
                System.exit(0);
            }

            /* System.out.println("private key: " + UtilHex.toHex(elgKpg.genKeyPair().getPrivate().getEncoded()).length());
            System.out.println("public key: " + UtilHex.toHex(elgKpg.genKeyPair().getPublic().getEncoded()).length());
             */
            FileOutputStream out1 = new FileOutputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//secret.asc");
            FileOutputStream out2 = new FileOutputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//pub.asc");

            exportKeyPair(out1, out2, dsaKp, elgKp, arg[1], arg[2].toCharArray(), true);
            System.out.println("Key pair generated!");
        } else {
            FileOutputStream out1 = new FileOutputStream("secret.bpg");
            FileOutputStream out2 = new FileOutputStream("pub.bpg");

            exportKeyPair(out1, out2, dsaKp, elgKp, arg[0], arg[1].toCharArray(), false);
        }
    }

    private void write_key() {

    }
}
