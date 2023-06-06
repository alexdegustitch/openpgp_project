/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package zp2020;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.filechooser.FileSystemView;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBEProtectionRemoverFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEProtectionRemoverFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author Aleksandar
 */
public class PrivringDump {

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

    public static void main(String[] args) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            //
            // Read the public key rings
            //
            //PGPPublicKeyRingCollection pubRings = new PGPPublicKeyRingCollection(
            //      PGPUtil.getDecoderStream(new FileInputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//basic-054a72a26aa4ed7fPUBLIC.asc")), new JcaKeyFingerprintCalculator());
            PGPSecretKeyRingCollection prvRings = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(new FileInputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//stic_krcko-51c366aca94b7bbcSECRET.asc")), new JcaKeyFingerprintCalculator());

            //Iterator rIt = pubRings.getKeyRings();
            Iterator rIt = prvRings.getKeyRings();
            //System.out.println(UtilHex.toHex(pubRings.));

            while (rIt.hasNext()) {
                //PGPPublicKeyRing pgpPub = (PGPPublicKeyRing) rIt.next();
                PGPSecretKeyRing pgpPrv = (PGPSecretKeyRing) rIt.next();

                try {
                    //pgpPub.getPublicKey();
                    pgpPrv.getSecretKey();
                } catch (Exception e) {
                    e.printStackTrace();
                    continue;
                }

                //Iterator it = pgpPub.getPublicKeys();
                Iterator it = pgpPrv.getSecretKeys();

                boolean first = true;
                while (it.hasNext()) {
                    //PGPPublicKey pgpKey = (PGPPublicKey) it.next();

                    PGPSecretKey pgpKey = (PGPSecretKey) it.next();

                    JcaPGPKeyConverter conv = new JcaPGPKeyConverter();

                    PGPPrivateKey pgpPrivKey = pgpKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build("z".toCharArray()));

                    PrivateKey pk = conv.getPrivateKey(pgpPrivKey);
                    System.out.println("BASIC PRIVATE KEY: " + UtilHex.toHex(pk.getEncoded()));
                    /*JcaPGPKeyConverter conv = new JcaPGPKeyConverter();
                    
                    Date dat = new Date(pgpKey.getPublicKey().getCreationTime().getTime());
                    LocalDate date = LocalDate.parse("2017-08-12", DateTimeFormatter.ISO_DATE);
                    
                    Date d = java.util.Date.from(date.atStartOfDay()
                    .atZone(ZoneId.systemDefault())
                    .toInstant());
                    
                    
                    //PGPDigestCalculator calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
                    
                    BcPGPDigestCalculatorProvider calc = new BcPGPDigestCalculatorProvider();
                    
                    
                    JcePBEProtectionRemoverFactory factory = new JcePBEProtectionRemoverFactory("a".toCharArray(), calc);
                    
                    PBESecretKeyDecryptor dec = factory.createDecryptor("");
                    
                    
                     */
                    if (first) {

                        System.out.println("=====PRIVATE KEY=====");
                        System.out.println("Key ID: " + Long.toHexString(pgpPrivKey.getKeyID()));
                        System.out.println("Key: " + UtilHex.toHex(pgpPrivKey.getPrivateKeyDataPacket().getEncoded()));

                        System.out.println("=====END PRIVATE KEY=====");

                        System.out.println("Key ID: " + Long.toHexString(pgpKey.getKeyID()));
                        System.out.println("Key: " + UtilHex.toHex(pgpKey.getEncoded()));
                        System.out.println("User ID: " + pgpKey.getUserIDs().next());

                        first = false;
                    } else {
                        System.out.println("=====PRIVATE KEY=====");
                        System.out.println("Key ID: " + Long.toHexString(pgpPrivKey.getKeyID()));
                        System.out.println("Key: " + UtilHex.toHex(pgpPrivKey.getPrivateKeyDataPacket().getEncoded()));

                        System.out.println("=====END PRIVATE KEY=====");

                        System.out.println("Key ID: " + Long.toHexString(pgpKey.getKeyID()) + " (subkey)");
                        System.out.println("Key: " + UtilHex.toHex(pgpKey.getEncoded()));
                        if (pgpKey.getUserIDs().hasNext()) {
                            System.out.println("User ID: " + pgpKey.getUserIDs().next());
                        }
                    }

                    System.out.println("=====PRIVATE KEY=====");

                    System.out.println("        Encoded Pub Key: " + UtilHex.toHex(pgpPrivKey.getPublicKeyPacket().getKey().getEncoded()) + "\n len: " + UtilHex.toHex(pgpPrivKey.getPublicKeyPacket().getKey().getEncoded()).length());
                    System.out.println("              Algorithm: " + getAlgorithm(pgpPrivKey.getPublicKeyPacket().getAlgorithm()));
                    // System.out.println("            Fingerprint: " + new String(Hex.encode(pgpKey.getPublicKey().getFingerprint())));

                    System.out.println("=====END PRIVATE KEY=====");

                    System.out.println("   Encryption Algorithm: " + getAlgorithm(pgpKey.getKeyEncryptionAlgorithm()));
                    System.out.println("              Algorithm: " + getAlgorithm(pgpKey.getPublicKey().getAlgorithm()));
                    System.out.println("            Fingerprint: " + new String(Hex.encode(pgpKey.getPublicKey().getFingerprint())));

                    //System.out.println("Finger: " + new String(Hex.encode(Fingerprint.calculateFingerprint(pgpKey.getEncoded()))));
                }
            }
        } catch (IOException ex) {
            Logger.getLogger(PrivringDump.class.getName()).log(Level.SEVERE, null, ex);
        } catch (PGPException ex) {
            //System.out.println("MORA SECRET");
           
            Logger.getLogger(PrivringDump.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
