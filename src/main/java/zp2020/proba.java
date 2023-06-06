/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package zp2020;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.filechooser.FileSystemView;
import javax.xml.bind.DatatypeConverter;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.misc.CAST5CBCParameters;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.bcpg.DSAPublicBCPGKey;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jcajce.provider.symmetric.CAST5;
import org.bouncycastle.jcajce.provider.util.SecretKeyUtil;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Aleksandar
 */
public class proba {

    private static final Base64 base64 = new Base64();

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.generateKeyPair();
    }

    public static void main(String[] args) throws Exception {

        String name = "aleks";
        String email = "aleksandar@gmail.com";
        String passphrase = "aleksa";

        int dsa_bits = 2048;
        int elgamal_bits = 2048;

        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA", "BC");
        keyPairGenerator.initialize(dsa_bits);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        DSAPrivateKey privateKey_dsa = (DSAPrivateKey) keyPair.getPrivate();
        DSAPublicKey publicKey_dsa = (DSAPublicKey) keyPair.getPublic();

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        byte[] hashedString = messageDigest.digest(passphrase.getBytes());

        System.out.println(hashedString.length);
        byte[] hash = new byte[16];
        for (int i = 0; i < hash.length; i++) {
            hash[i] = hashedString[i];
        }
        SecretKey originalKey = new SecretKeySpec(hash, 0, hash.length, "CAST5");

        /*KeyGenerator keyGen = KeyGenerator.getInstance("CAST5", "BC");

        SecretKey key_cast = keyGen.generateKey();*/
        //System.out.println("original " + UtilHex.toHex(originalKey.getEncoded()));
        Cipher c = Cipher.getInstance("CAST5", "BC");
        c.init(Cipher.ENCRYPT_MODE, originalKey);

        byte[] cipher_text_dsa = c.doFinal(privateKey_dsa.getEncoded());

        //System.out.println("cipher text: " + UtilHex.toHex(cipher_text));
        /*
        KeyGenerator key_aes_gen = KeyGenerator.getInstance("AES", "BC");
        key_aes_gen.init(128);
        
        Key key_aes = key_aes_gen.generateKey();
        
        Cipher cipher_aes = Cipher.getInstance("AES", "BC");
        cipher_aes.init(Cipher.ENCRYPT_MODE, key_aes);
        byte[] cipher_aes_text = cipher_aes.doFinal(privateKey.getEncoded());
        
        System.out.println("aes cipher: " + UtilHex.toHex(cipher_aes_text));
         */
        //ovo cuvam u key ringu
        KeyPairGenerator elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        BigInteger g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        BigInteger p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

        DHParameterSpec elParams = new DHParameterSpec(p, g);

        elgKpg.initialize(elParams);
        elgKpg.initialize(elgamal_bits);

        //
        // this is quicker because we are using pregenerated parameters.
        //
        KeyPair elgKp = elgKpg.generateKeyPair();

        ElGamalPrivateKey privateKey_elgamal = (ElGamalPrivateKey) elgKp.getPrivate();
        ElGamalPublicKey publicKey_elgamal = (ElGamalPublicKey) elgKp.getPublic();

        messageDigest = MessageDigest.getInstance("SHA-1");
        hashedString = messageDigest.digest(passphrase.getBytes());

        System.out.println(hashedString.length);
        hash = new byte[16];
        for (int i = 0; i < hash.length; i++) {
            hash[i] = hashedString[i];
        }
        SecretKey originalKey_elgamal = new SecretKeySpec(hash, 0, hash.length, "CAST5");

        c = Cipher.getInstance("CAST5", "BC");
        c.init(Cipher.ENCRYPT_MODE, originalKey_elgamal);

        byte[] cipher_text_elgamal = c.doFinal(privateKey_elgamal.getEncoded());

        File private_keyring = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//ring_private_keys.txt");

        Scanner in = new Scanner(new InputStreamReader(new FileInputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//ring_private_keys.txt"), StandardCharsets.UTF_8));

        byte[] key_id = publicKey_dsa.getEncoded();
        int index = key_id.length;

        byte[] res = new byte[8];
        int i = 0;
        while (i < 8) {
            i++;
            index--;
            res[8 - i] = key_id[index];
        }

        LocalDate now = LocalDate.now();
        StringBuilder sb = new StringBuilder();
        byte[] res_old = res;
        //dsa master key
        sb.append(now.toString() + " ");
        sb.append(name + "<" + email + "> ");
        sb.append(UtilHex.toHex(res) + " ");
        sb.append(UtilHex.toHex(publicKey_dsa.getEncoded()) + " ");
        sb.append("DSA ");
        sb.append(base64.encodeToString(cipher_text_dsa) + " \n");

        key_id = publicKey_elgamal.getEncoded();
        index = key_id.length;

        res = new byte[8];
        i = 0;
        while (i < 8) {
            i++;
            index--;
            res[8 - i] = key_id[index];
        }

        //String pubKeyPEM = publicK.replace("-----BEGIN PUBLIC KEY-----\n", "").replace("-----END PUBLIC KEY-----", "");
        //String pub_string = UtilHex.toHex(publicKey_dsa.getEncoded());
        // Base64 decode the data
        //byte[] encodedPublicKey = base64.decode(UtilHex.toHex(publicKey_dsa.getEncoded()));

        //System.out.println("PK: " + UtilHex.toHex(encodedPublicKey));

        X509EncodedKeySpec spec = new X509EncodedKeySpec(DatatypeConverter.parseHexBinary(UtilHex.toHex(publicKey_dsa.getEncoded())));
        KeyFactory kf = KeyFactory.getInstance("DSA");
        //System.out.println(kf.generatePublic(spec));

        PublicKey k_pub = kf.generatePublic(spec);

        System.out.println("public key real: " + UtilHex.toHex(publicKey_dsa.getEncoded()));
        System.out.println("public key: " + k_pub.getAlgorithm() + ", " + UtilHex.toHex(k_pub.getEncoded()));

        //elgamal subkey
        sb.append(now.toString() + " ");
        sb.append(name + "<" + email + "> ");
        sb.append(UtilHex.toHex(res) + " ");
        sb.append(UtilHex.toHex(publicKey_elgamal.getEncoded()) + " ");
        sb.append("ELGAMAL ");
        sb.append(base64.encodeToString(cipher_text_elgamal) + " ");
        sb.append(UtilHex.toHex(res_old) + " \n");

        StringBuilder sbb = new StringBuilder();
        sbb.append("-----BEGIN PGP PRIVATE KEY BLOCK-----\n");
        sbb.append(base64.encodeToString(publicKey_dsa.getEncoded()) + "\n");
        sbb.append("-----END PGP PRIVATE KEY BLOCK-----");

        ElGamalPublicKey pd = (ElGamalPublicKey) publicKey_elgamal;

        try {
            Files.write(Paths.get(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//private_keyring.txt"), sb.toString().getBytes(), StandardOpenOption.APPEND);
            Files.deleteIfExists(Paths.get(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//public.asc"));
            File ring_private_keys = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp/public.asc");
            ring_private_keys.createNewFile();
            Files.write(Paths.get(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//public.asc"), sbb.toString().getBytes(), StandardOpenOption.WRITE);

        } catch (IOException e) {
            //exception handling left as an exercise for the reader
        } finally {

        }

    }

}
