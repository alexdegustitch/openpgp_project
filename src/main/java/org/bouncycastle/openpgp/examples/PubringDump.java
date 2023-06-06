package org.bouncycastle.openpgp.examples;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.security.Security;
import java.util.Base64;
import java.util.Iterator;
import javax.swing.filechooser.FileSystemView;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.encoders.Hex;
import zp2020.UtilHex;

/**
 * Basic class which just lists the contents of the public key file passed as an
 * argument. If the file contains more than one "key ring" they are listed in
 * the order found.
 */
public class PubringDump {

    public static String getAlgorithm(
            int algId) {
        switch (algId) {
            case PublicKeyAlgorithmTags.RSA_GENERAL:
                return "RSA_GENERAL";
            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
                return "RSA_ENCRYPT";
            case PublicKeyAlgorithmTags.RSA_SIGN:
                return "RSA_SIGN";
            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
                return "ELGAMAL_ENCRYPT";
            case PublicKeyAlgorithmTags.DSA:
                return "DSA";
            case PublicKeyAlgorithmTags.ECDH:
                return "ECDH";
            case PublicKeyAlgorithmTags.ECDSA:
                return "ECDSA";
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
                return "ELGAMAL_GENERAL";
            case PublicKeyAlgorithmTags.DIFFIE_HELLMAN:
                return "DIFFIE_HELLMAN";
        }

        return "unknown";
    }

    public static void main(String[] args)
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        //
        // Read the public key rings
        //
        PGPPublicKeyRingCollection pubRings = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(new FileInputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//basic-054a72a26aa4ed7fPUBLIC.asc")), new JcaKeyFingerprintCalculator());

        Iterator rIt = pubRings.getKeyRings();
        //System.out.println(UtilHex.toHex(pubRings.));

        while (rIt.hasNext()) {
            PGPPublicKeyRing pgpPub = (PGPPublicKeyRing) rIt.next();

            try {
                pgpPub.getPublicKey();
            } catch (Exception e) {
                e.printStackTrace();
                continue;
            }

            Iterator it = pgpPub.getPublicKeys();
            
            boolean first = true;
            while (it.hasNext()) {
                PGPPublicKey pgpKey = (PGPPublicKey) it.next();

                if (first) {
                    System.out.println("Key ID: " + Long.toHexString(pgpKey.getKeyID()));
                    System.out.println("Key: " + UtilHex.toHex(pgpKey.getEncoded()));
                    System.out.println("User ID: " + pgpKey.getUserIDs().next());
                    Iterator s = pgpKey.getSignatures();
                    while (s.hasNext()) {
                        PGPSignature p = (PGPSignature) s.next();

                        System.out.println("sign: " + UtilHex.toHex(p.getEncoded()));

                    }
                    System.out.println("pass: ");
                    first = false;
                } else {
                    System.out.println("Key ID: " + Long.toHexString(pgpKey.getKeyID()) + " (subkey)");
                    System.out.println("Key: " + UtilHex.toHex(pgpKey.getEncoded()));
                    if (pgpKey.getUserIDs().hasNext()) {
                        System.out.println("User ID: " + pgpKey.getUserIDs().next());
                    }
                }
                System.out.println("            Algorithm: " + getAlgorithm(pgpKey.getAlgorithm()));
                System.out.println("            Fingerprint: " + new String(Hex.encode(pgpKey.getFingerprint())));
                System.out.println("Finger: " + new String(Hex.encode(Fingerprint.calculateFingerprint(pgpKey.getEncoded()))));
            }
        }
    }
}
