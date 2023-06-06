package chapter4;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;

/**
 * El Gamal example with random key generation.
 */
public class RandomKeyElGamalExample {

    public static void main(
            String[] args)
            throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        byte[] input = new byte[]{(byte) 'a', (byte) 'k', (byte) 'i'};
        Cipher cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");

        SecureRandom random = Utils.createFixedRandom();

        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ElGamal", "BC");

        generator.initialize(256, random);

        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();
        Key privKey = pair.getPrivate();

        System.out.println("input : " + Utils.toHex(input));

        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);

        byte[] cipherText = cipher.doFinal(input);

        System.out.println("cipher: " + Utils.toHex(cipherText));

        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, privKey);

        byte[] plainText = cipher.doFinal(cipherText);

        System.out.println("plain : " + Utils.toHex(plainText));
    }
}
