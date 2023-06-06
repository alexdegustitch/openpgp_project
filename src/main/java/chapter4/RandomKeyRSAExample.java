package chapter4;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * RSA example with random key generation.
 */
public class RandomKeyRSAExample
{
    public static void main(
        String[]    args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        String lozinka = "aki";
        byte[]           input = lozinka.getBytes();
        Cipher	         cipher = Cipher.getInstance("CAST5", "BC");
        SecureRandom     random = Utils.createFixedRandom();
        
        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("CAST5", "BC");
        
        generator.initialize(2048, random);

        KeyPair          pair = generator.generateKeyPair();
        Key              pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();

        System.out.println("input : " + Utils.toHex(input));
        
        // encryption step
        
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);

        byte[] cipherText = cipher.doFinal(input);

        System.out.println("cipher: " + Utils.toHex(cipherText) + ", size: " + Utils.toHex(cipherText).length());
        
        // decryption step

        cipher.init(Cipher.DECRYPT_MODE, privKey);

        byte[] plainText = cipher.doFinal(cipherText);
        
        System.out.println("plain : " + Utils.toHex(plainText));
    }
}
