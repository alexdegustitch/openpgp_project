/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package zp2020;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.filechooser.FileSystemView;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.util.Fingerprint;
import static zp2020.PrivringDump.getAlgorithm;

/**
 *
 * @author Aleksandar
 */
public class UtilImport {

    private static boolean mk_added = false, sk_added = false;

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

    public static String import_public(String file_name, List<MyMasterKey> master_keys, List<MySubKey> sub_keys) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            //
            // Read the public key rings
            //
            PGPPublicKeyRingCollection pubRings = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(new FileInputStream(file_name)), new JcaKeyFingerprintCalculator());

            Iterator rIt = pubRings.getKeyRings();
            //System.out.println(UtilHex.toHex(pubRings.));
            mk_added = false;
            sk_added = false;
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
                String master_key_id = null;
                while (it.hasNext()) {
                    PGPPublicKey pgpKey = (PGPPublicKey) it.next();

                    JcaPGPKeyConverter conv = new JcaPGPKeyConverter();

                    PublicKey pub = conv.getPublicKey(pgpKey);

                    LocalDate date = Instant.ofEpochMilli(pgpKey.getCreationTime().getTime())
                            .atZone(ZoneId.systemDefault())
                            .toLocalDate();

                    if (first) {

                        DSAPublicKey pub_dsa = (DSAPublicKey) pub;
                        MyMasterKey mk = new MyMasterKey();

                        for (int i = 0; i < master_keys.size(); i++) {
                            if (master_keys.get(i).getKey_id().equals(Long.toHexString(pgpKey.getKeyID()))) {
                                if (master_keys.get(i).isPr_key()) {
                                    return "private_exists";
                                } else {
                                    return "public_exists";
                                }
                            }
                        }

                        String[] user_id = pgpKey.getUserIDs().next().split("<");

                        /*if (user_id[0].lastIndexOf("") == user_id.length - 1) {
                            user_id[0] = user_id[0].substring(0, user_id[0].length() - 1);
                        }*/
                        mk.setName(user_id[0]);
                        mk.setEmail(user_id[1].substring(0, user_id[1].length() - 1));
                        mk.setType(getAlgorithm(pgpKey.getAlgorithm()));
                        mk.setKey_id(Long.toHexString(pgpKey.getKeyID()));
                        String key_Id = mk.getKey_id();
                        if (mk.getKey_id().length() < 16) {
                            for (int i = 0; i < 16 - mk.getKey_id().length(); i++) {
                                key_Id = "0" + key_Id;
                            }
                        }
                        mk.setKey_id(key_Id);
                        mk.setValid_from(date.toString());
                        mk.setPublic_key(UtilHex.toHex(pub_dsa.getEncoded()));
                        mk.setDate(pgpKey.getCreationTime());
                        
                        mk.setPr_key(false);
                        master_key_id = mk.getKey_id();

                        //enkripcije privatnog kljuca nema
                        /*
                        System.out.println("Key ID: " + Long.toHexString(pgpKey.getKeyID()));
                        System.out.println("Key: " + UtilHex.toHex(pgpKey.getEncoded()));
                        System.out.println("User ID: " + pgpKey.getUserIDs().next());*/
                        master_keys.add(mk);
                        mk_added = true;
                        /*
                        System.out.println("Key ID: " + Long.toHexString(pgpKey.getKeyID()));
                        System.out.println("Key: " + UtilHex.toHex(pgpKey.getEncoded()));
                        System.out.println("User ID: " + pgpKey.getUserIDs().next());*/
                        first = false;
                    } else {

                        ElGamalPublicKey pub_elg = (ElGamalPublicKey) pub;

                        MySubKey sk = new MySubKey();

                        //System.out.println("user id: " + pgpKey.getUserIDs().next());
                        //String[] user_id = pgpKey.getPublicKey().getUserIDs().next().split("<");
                        sk.setName(master_keys.get(master_keys.size() - 1).getName());
                        sk.setEmail(master_keys.get(master_keys.size() - 1).getEmail());
                        sk.setType(getAlgorithm(pgpKey.getAlgorithm()));
                        sk.setKey_id(Long.toHexString(pgpKey.getKeyID()));
                        String key_Id = sk.getKey_id();
                        if (sk.getKey_id().length() < 16) {
                            for (int i = 0; i < 16 - sk.getKey_id().length(); i++) {
                                key_Id = "0" + key_Id;
                            }
                        }
                        sk.setKey_id(key_Id);
                        sk.setValid_from(date.toString());
                        sk.setPublic_key(UtilHex.toHex(pub_elg.getEncoded()));
                        sk.setMaster_key_id(master_key_id);
                        sk.setDate(pgpKey.getCreationTime());

                        //nema  enkripcije privatnog kljuca
                        sub_keys.add(sk);
                        sk_added = true;
                        /*
                        System.out.println("Key ID: " + Long.toHexString(pgpKey.getKeyID()) + " (subkey)");
                        System.out.println("Key: " + UtilHex.toHex(pgpKey.getEncoded()));
                        if (pgpKey.getUserIDs().hasNext()) {
                            System.out.println("User ID: " + pgpKey.getUserIDs().next());
                        }*/
                    }
                    /*  Hex h = new Hex();
                    System.out.println("            Algorithm: " + getAlgorithm(pgpKey.getAlgorithm()));
                    System.out.println("            Fingerprint: " + new String(h.encode(pgpKey.getFingerprint())));*/

                }
            }
        } catch (PGPException ex) {

            if (mk_added == true) {
                master_keys.remove(master_keys.size() - 1);
            }
            if (sk_added == true) {
                sub_keys.remove(sub_keys.size() - 1);
            }

            if (ex.getMessage().startsWith("checksum")) {
                return "bad_pass";
            } else {
                return "secret_key";
            }

        } catch (IOException ex) {
            if (mk_added == true) {
                master_keys.remove(master_keys.size() - 1);
            }
            if (sk_added == true) {
                sub_keys.remove(sub_keys.size() - 1);
            }
            Logger.getLogger(UtilImport.class.getName()).log(Level.SEVERE, null, ex);
        }

        mk_added = false;
        sk_added = false;

        Utils.add_public_key(master_keys.get(master_keys.size() - 1), sub_keys.get(sub_keys.size() - 1));
        return "ok";
    }

    public static String import_secret(String file_name, String pass, List<MyMasterKey> master_keys, List<MySubKey> sub_keys) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            //
            // Read the public key rings
            //
            //PGPPublicKeyRingCollection pubRings = new PGPPublicKeyRingCollection(
            //      PGPUtil.getDecoderStream(new FileInputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//basic-054a72a26aa4ed7fPUBLIC.asc")), new JcaKeyFingerprintCalculator());
            PGPSecretKeyRingCollection prvRings = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(new FileInputStream(file_name)), new JcaKeyFingerprintCalculator());

            //Iterator rIt = pubRings.getKeyRings();
            Iterator rIt = prvRings.getKeyRings();
            //System.out.println(UtilHex.toHex(pubRings.));

            mk_added = false;
            sk_added = false;
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
                String master_key_id = null;
                while (it.hasNext()) {
                    //PGPPublicKey pgpKey = (PGPPublicKey) it.next();

                    PGPSecretKey pgpKey = (PGPSecretKey) it.next();
                    JcaPGPKeyConverter conv = new JcaPGPKeyConverter();
                    PGPPrivateKey pgpPrivKey = pgpKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass.toCharArray()));
                    PrivateKey pk = conv.getPrivateKey(pgpPrivKey);
                    PublicKey pub = conv.getPublicKey(pgpKey.getPublicKey());

                    LocalDate date = Instant.ofEpochMilli(pgpKey.getPublicKey().getCreationTime().getTime())
                            .atZone(ZoneId.systemDefault())
                            .toLocalDate();

                    
                    //boolean delete_public_key = false;
                    if (first) {

                        for (int i = 0; i < master_keys.size(); i++) {
                            if (master_keys.get(i).getKey_id().equals(Long.toHexString(pgpKey.getKeyID()))) {
                                if (master_keys.get(i).isPr_key()) {
                                    return "private_exists";
                                } else {

                                    Utils.remove_key(master_keys.get(i).getKey_id(), i);
                                    System.out.println("desilo se");
                                    //delete_public_key = true;
                                    break;
                                }
                            }
                        }

                        DSAPrivateKey pk_dsa = (DSAPrivateKey) pk;
                        DSAPublicKey pub_dsa = (DSAPublicKey) pub;
                        MyMasterKey mk = new MyMasterKey();

                        String[] user_id = pgpKey.getUserIDs().next().split("<");

                        /*if (user_id[0].lastIndexOf("") == user_id.length - 1) {
                            user_id[0] = user_id[0].substring(0, user_id[0].length() - 1);
                        }*/

                        mk.setName(user_id[0]);
                        mk.setEmail(user_id[1].substring(0, user_id[1].length() - 1));
                        mk.setType(getAlgorithm(pgpKey.getPublicKey().getAlgorithm()));
                        mk.setKey_id(Long.toHexString(pgpKey.getPublicKey().getKeyID()));
                        String key_Id = mk.getKey_id();
                        if (mk.getKey_id().length() < 16) {
                            for (int i = 0; i < 16 - mk.getKey_id().length(); i++) {
                                key_Id = "0" + key_Id;
                            }
                        }
                        mk.setKey_id(key_Id);
                        mk.setValid_from(date.toString());
                        mk.setPublic_key(UtilHex.toHex(pub_dsa.getEncoded()));
                        mk.setDate(pgpKey.getPublicKey().getCreationTime());
                        
                        mk.setPr_key(true);
                        master_key_id = mk.getKey_id();
                        //enkripcija privatnog kljuca
                        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
                        byte[] hashedString = messageDigest.digest(pass.getBytes());

                        //System.out.println(hashedString.length);
                        byte[] hash = new byte[16];
                        for (int i = 0; i < hash.length; i++) {
                            hash[i] = hashedString[i];
                        }

                        SecretKey originalKey = new SecretKeySpec(hash, 0, hash.length, "CAST5");

                        Cipher c = Cipher.getInstance("CAST5", "BC");
                        c.init(Cipher.ENCRYPT_MODE, originalKey);

                        byte[] cipher_text_dsa = c.doFinal(pk_dsa.getEncoded());

                        String cipher_key = Base64.getEncoder().encodeToString(cipher_text_dsa);

                        mk.setPrivate_key(cipher_key);
                        /*
                        System.out.println("Key ID: " + Long.toHexString(pgpKey.getKeyID()));
                        System.out.println("Key: " + UtilHex.toHex(pgpKey.getEncoded()));
                        System.out.println("User ID: " + pgpKey.getUserIDs().next());*/
                        master_keys.add(mk);
                        mk_added = true;
                        first = false;
                    } else {

                        ElGamalPrivateKey pk_elg = (ElGamalPrivateKey) pk;
                        ElGamalPublicKey pub_elg = (ElGamalPublicKey) pub;

                        MySubKey sk = new MySubKey();

                        //System.out.println("user id: " + pgpKey.getUserIDs().next());
                        //String[] user_id = pgpKey.getPublicKey().getUserIDs().next().split("<");
                        sk.setName(master_keys.get(master_keys.size() - 1).getName());
                        sk.setEmail(master_keys.get(master_keys.size() - 1).getEmail());
                        sk.setType(getAlgorithm(pgpKey.getPublicKey().getAlgorithm()));

                        sk.setKey_id(Long.toHexString(pgpKey.getPublicKey().getKeyID()));
                        String key_Id = sk.getKey_id();
                        if (sk.getKey_id().length() < 16) {
                            for (int i = 0; i < 16 - sk.getKey_id().length(); i++) {
                                key_Id = "0" + key_Id;
                            }
                        }
                        sk.setKey_id(key_Id);
                        sk.setValid_from(date.toString());
                        sk.setPublic_key(UtilHex.toHex(pub_elg.getEncoded()));
                        sk.setMaster_key_id(master_key_id);
                        sk.setDate(pgpKey.getPublicKey().getCreationTime());
                        
                        //enkripcija privatnog kljuca
                        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
                        byte[] hashedString = messageDigest.digest(pass.getBytes());

                        //System.out.println(hashedString.length);
                        byte[] hash = new byte[16];
                        for (int i = 0; i < hash.length; i++) {
                            hash[i] = hashedString[i];
                        }

                        SecretKey originalKey = new SecretKeySpec(hash, 0, hash.length, "CAST5");

                        Cipher c = Cipher.getInstance("CAST5", "BC");
                        c.init(Cipher.ENCRYPT_MODE, originalKey);

                        byte[] cipher_text_elg = c.doFinal(pk_elg.getEncoded());

                        String cipher_key = Base64.getEncoder().encodeToString(cipher_text_elg);

                        sk.setPrivate_key(cipher_key);

                        sub_keys.add(sk);
                        sk_added = true;
                        /*
                        System.out.println("Key ID: " + Long.toHexString(pgpKey.getKeyID()) + " (subkey)");
                        System.out.println("Key: " + UtilHex.toHex(pgpKey.getEncoded()));
                        if (pgpKey.getUserIDs().hasNext()) {
                            System.out.println("User ID: " + pgpKey.getUserIDs().next());
                        }*/
                    }
                    /* System.out.println("   Encryption Algorithm: " + getAlgorithm(pgpKey.getKeyEncryptionAlgorithm()));
                    System.out.println("              Algorithm: " + getAlgorithm(pgpKey.getPublicKey().getAlgorithm()));
                    System.out.println("            Fingerprint: " + new String(org.bouncycastle.util.encoders.Hex.encode(pgpKey.getPublicKey().getFingerprint())));*/
                    //System.out.println("Finger: " + new String(Hex.encode(Fingerprint.calculateFingerprint(pgpKey.getEncoded()))));
                }
            }
        } catch (PGPException ex) {

            if (mk_added == true) {
                master_keys.remove(master_keys.size() - 1);
            }
            if (sk_added == true) {
                sub_keys.remove(sub_keys.size() - 1);
            }

            if (ex.getMessage().startsWith("checksum")) {
                return "bad_pass";
            } else {
                return "public_key";
            }

        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            if (mk_added == true) {
                master_keys.remove(master_keys.size() - 1);
            }
            if (sk_added == true) {
                sub_keys.remove(sub_keys.size() - 1);
            }
            Logger.getLogger(UtilImport.class.getName()).log(Level.SEVERE, null, ex);
        }

        mk_added = false;
        sk_added = false;

        Utils.add_private_key(master_keys.get(master_keys.size() - 1), sub_keys.get(sub_keys.size() - 1));
        return "ok";
    }

    private static String get_key_id_format(String key_id) {
        key_id = key_id.toUpperCase();
        return key_id.substring(0, 4) + " " + key_id.substring(4, 8) + " " + key_id.substring(8, 12) + " " + key_id.substring(12, 16);
    }
}
