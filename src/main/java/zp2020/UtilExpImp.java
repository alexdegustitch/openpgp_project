/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package zp2020;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.filechooser.FileSystemView;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author Aleksandar
 */
public class UtilExpImp {

    private static final Base64 base64 = new Base64();

    public static void generate_key_pair(MyMasterKey mk, MySubKey sk, String pass) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            //provera da li je pass ok
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            byte[] hashedString = messageDigest.digest(pass.getBytes());

            System.out.println(hashedString.length);
            byte[] hash = new byte[16];
            for (int i = 0; i < hash.length; i++) {
                hash[i] = hashedString[i];
            }

            Cipher c = Cipher.getInstance("CAST5", "BC");

            SecretKeySpec originalKey = new SecretKeySpec(hash, "CAST5");

            c.init(Cipher.DECRYPT_MODE, originalKey);

            byte[] decordedValue = base64.decode(mk.getPrivate_key().getBytes());

            byte[] decrypted_private_key = c.doFinal(decordedValue);

            //generisanje para DSA kljuceva
            KeyFactory kf = KeyFactory.getInstance("DSA");

            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(decrypted_private_key));

            X509EncodedKeySpec keySpecX509
                    = new X509EncodedKeySpec(Hex.decode(mk.getPublic_key()));

            //System.out.println("keySpec: " + mk.getPublic_key());
            PublicKey publickey = kf.generatePublic(keySpecX509);

            /*Signature signature = Signature.getInstance("DSA", "BC");
            signature.initSign(privateKey);

            byte[] message = new byte[]{(byte) 'a', (byte) 'b', (byte) 'c'};

            signature.update(message);

            byte[] sigBytes = signature.sign();

            // verify a signature
            signature.initVerify(publickey);

            signature.update(message);*/
            //elgamal key
            Cipher c_elg = Cipher.getInstance("CAST5", "BC");

            SecretKeySpec originalKey_elg = new SecretKeySpec(hash, "CAST5");

            c_elg.init(Cipher.DECRYPT_MODE, originalKey_elg);

            byte[] decordedValue_elg = base64.decode(sk.getPrivate_key().getBytes());

            byte[] decrypted_private_key_elg = c_elg.doFinal(decordedValue_elg);

            KeyFactory kf_elg = KeyFactory.getInstance("ELGAMAL", "BC");

            PrivateKey privateKey_elg = kf_elg.generatePrivate(new PKCS8EncodedKeySpec(decrypted_private_key_elg));

            X509EncodedKeySpec keySpecX509elg
                    = new X509EncodedKeySpec(Hex.decode(sk.getPublic_key()));

            PublicKey publickey_elg = kf_elg.generatePublic(keySpecX509elg);

            JcaPGPKeyConverter conv = new JcaPGPKeyConverter();

            //datum
            LocalDate date = LocalDate.parse(mk.getValid_from(), DateTimeFormatter.ISO_DATE);

            Date d = java.util.Date.from(date.atStartOfDay()
                    .atZone(ZoneId.systemDefault())
                    .toInstant());

            System.out.println("d " + d.toString());

            PGPPublicKey pk = null;
            if (mk.getDate() != null) {
                pk = conv.getPGPPublicKey(PublicKeyAlgorithmTags.DSA, publickey, mk.getDate());
            } else {
                pk = conv.getPGPPublicKey(PublicKeyAlgorithmTags.DSA, publickey, d);
            }

            System.out.println("pk key " + Long.toHexString(pk.getKeyID()));

            KeyPair dsaKp = new KeyPair(publickey, privateKey);

            KeyPair elgKp = new KeyPair(publickey_elg, privateKey_elg);

            if (mk.getDate() != null) {
                d = mk.getDate();
                System.out.println("date: " + d.toString());
            }

            FileOutputStream out_public;
            try ( FileOutputStream out_secret = new FileOutputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + mk.getName() + "_" + mk.getKey_id() + "SECRET.asc")) {
                Utils.exportSecretKey(out_secret, dsaKp, elgKp, mk.getName() + "<" + mk.getEmail() + ">", pass.toCharArray(), true, d);
                out_public = new FileOutputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + mk.getName() + "_" + mk.getKey_id() + "PUBLIC.asc");
                Utils.exportPublicKey(out_public, dsaKp, elgKp, mk.getName() + "<" + mk.getEmail() + ">", pass.toCharArray(), true, d);
            }
            out_public.close();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException | SignatureException | PGPException | IOException ex) {
            Logger.getLogger(UtilExpImp.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
