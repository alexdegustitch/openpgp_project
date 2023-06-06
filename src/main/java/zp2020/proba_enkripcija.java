/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package zp2020;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Iterator;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.filechooser.FileSystemView;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

/**
 *
 * @author Aleksandar
 */
public class proba_enkripcija {

    public static void main(String[] args) throws IOException {

        Scanner scanInput = new Scanner(System.in);
        System.out.println("Unesi broj: ");
        int index = scanInput.nextInt();
        while (index >= 0) {
            switch (index) {
                case 0: {
                    FileInputStream keyIn = null;
                    try {
                        String file_name = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//test3.txt";
                        Security.addProvider(new BouncyCastleProvider());
                        keyIn = new FileInputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//stic_ea380314b6bbad63_SECRET.asc");
                        FileOutputStream out = new FileOutputStream(file_name + ".asc");

                        signFile(file_name, keyIn, out, "s".toCharArray(), true);
                        out.close();
                        System.out.println("File is signed!");
                    } catch (FileNotFoundException ex) {
                        Logger.getLogger(proba_enkripcija.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | PGPException | SignatureException ex) {
                        Logger.getLogger(proba_enkripcija.class.getName()).log(Level.SEVERE, null, ex);
                    } finally {
                        try {
                            if (keyIn != null) {
                                keyIn.close();
                            }
                        } catch (IOException ex) {
                            Logger.getLogger(proba_enkripcija.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                    break;
                }
                case 1: {
                    try {
                        Security.addProvider(new BouncyCastleProvider());
                        String outputFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//done";
                        String inputFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//test_file.txt";
                        String encKey = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//neca_0x5247785F_public.asc";
                        String encKey2 = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//helena_0xB07C4968_public.asc";

                        encryptFile(inputFileName + ".asc", inputFileName, encKey, encKey2, true, true);

                        System.out.println("File is encrypted!");
                    } catch (IOException | NoSuchProviderException | PGPException ex) {
                        Logger.getLogger(proba_enkripcija.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
                break;

                case 2: {
                    InputStream keyIn = null;
                    try {
                        Security.addProvider(new BouncyCastleProvider());
                        String key = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//helena_0xB07C4968_SECRET.asc";
                        String filename = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//test_file.txt";
                        keyIn = PGPUtil.getDecoderStream(new FileInputStream(key));
                        FileOutputStream out = new FileOutputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//test_file_c.txt" + ".asc");

                        signFile(filename, keyIn, out, "s".toCharArray(), "SHA1");

                        String outputFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//done";
                        String inputFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//test_file_c.txt.asc";
                        String encKey = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//neca_0x5247785F_public.asc";
                        //encryptFile(outputFileName + ".asc", inputFileName, encKey, true, true);

                        System.out.println("File is signed without compression and encrypted!");
                    } catch (FileNotFoundException ex) {
                        Logger.getLogger(proba_enkripcija.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | PGPException | SignatureException ex) {
                        Logger.getLogger(proba_enkripcija.class.getName()).log(Level.SEVERE, null, ex);
                    } finally {
                        try {

                            if (keyIn != null) {
                                keyIn.close();
                            }
                        } catch (IOException ex) {
                            Logger.getLogger(proba_enkripcija.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }

                    break;

                }

                case 3: {
                    try {
                        Security.addProvider(new BouncyCastleProvider());
                        String secretKey = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//helena_0xB07C4968_SECRET.asc";
                        String publicKey = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//neca_0x5247785F_public.asc";
                        String inputFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//test_file.txt";
                        String outputFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//test_file.txt" + ".asc";
                        String pass = "s";

                        /*if (signEncrypt(outputFileName, inputFileName, publicKey, secretKey, pass)) {
                            System.out.println("File is signed and encrypted!");
                        } else {
                            System.out.println("Error occured!");
                        }*/
                    } catch (Exception ex) {
                        Logger.getLogger(proba_enkripcija.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    break;
                }

                case 4: {

                    try {
                        Security.addProvider(new BouncyCastleProvider());

                        String inputFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//test_test.txt.sig";
                        String fileName = inputFileName.substring(0, inputFileName.length() - 3);

                        String keyFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//stic_0xE78EDCFC_public.asc";

                        verifySignature(fileName, inputFileName, keyFileName);
                        
                        break;
                    } catch (GeneralSecurityException | PGPException ex) {
                        Logger.getLogger(proba_enkripcija.class.getName()).log(Level.SEVERE, null, ex);
                    }

                    break;
                }
                case 5: {
                    try {
                        String inputFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//test_file.txt.asc";
                        String keyFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//helena_0xB07C4968_public.asc";

                        FileInputStream in = new FileInputStream(inputFileName);
                        FileInputStream keyIn = new FileInputStream(keyFileName);

                        verifyFile(in, keyIn);
                    } catch (Exception ex) {
                        Logger.getLogger(proba_enkripcija.class.getName()).log(Level.SEVERE, null, ex);
                    }

                    break;
                }
                case 6: {
                    try {
                        String inputFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//test_file.txt.asc";
                        String keyFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//neca_0x5247785F_SECRET.asc";
                        String outputFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//test_file.txt";

                        String pass = "a";
                        if (decrypt(inputFileName, keyFileName, outputFileName, pass)) {
                            System.out.println("File is decrypted!");
                        } else {
                            System.out.println("Error occured!");
                        }

                    } catch (Exception ex) {
                        Logger.getLogger(proba_enkripcija.class.getName()).log(Level.SEVERE, null, ex);
                    }

                    break;
                }
                case 7: {
                    try {
                        String inputFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//test_file.txt.asc";
                        //String keyFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//neca_0x5247785F_SECRET.asc";
                        //String outputFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//test_file.txt";

                        String pass = "s";
                        decryptFile(inputFileName, pass.toCharArray());

                        System.out.println("File is decrypted!");
                    } catch (IOException | NoSuchProviderException | PGPException ex) {
                        Logger.getLogger(proba_enkripcija.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    break;
                }
                case 8: {
                    try {
                        Security.addProvider(new BouncyCastleProvider());
                        String inputFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//test.txt.asc";
                        String keyFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//neca_70cb1585b41bddbe_PUBLIC.asc";
                        String keyFileSign = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//neca_70cb1585b41bddbe_PUBLIC.asc";
                        String outputFileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//test.txt";
                        String pass = "n";
                        decryptFile(inputFileName, keyFileName, pass.toCharArray(), outputFileName, keyFileSign);
                        System.out.println("File is decrypted!");
                        break;
                    } catch (NoSuchProviderException ex) {
                        Logger.getLogger(proba_enkripcija.class.getName()).log(Level.SEVERE, null, ex);
                    }

                    break;
                }

                case 9: {

                    try {
                        Security.addProvider(new BouncyCastleProvider());
                        String fileName = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//test_test.txt.sig";
                        FileInputStream in = new FileInputStream(fileName);
                        String key = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//stic_0xE78EDCFC_public.asc";
                        InputStream keyIn = PGPUtil.getDecoderStream(new FileInputStream(key));

                        verifyFile(in, keyIn);
                    } catch (Exception ex) {
                        Logger.getLogger(proba_enkripcija.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }

            }
            System.out.println("Unesi broj: ");
            index = scanInput.nextInt();
        }
    }

    private static void verifyFile(
            InputStream in,
            InputStream keyIn)
            throws Exception {
        in = PGPUtil.getDecoderStream(in);

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);

        Object message = pgpFact.nextObject();

        if (message instanceof PGPCompressedData) {
            PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();
            pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

            PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) pgpFact.nextObject();

            PGPOnePassSignature ops = p1.get(0);

            PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();

            InputStream dIn = p2.getInputStream();
            int ch;
            PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

            PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());
            FileOutputStream out = new FileOutputStream(p2.getFileName());

            ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

            while ((ch = dIn.read()) >= 0) {
                ops.update((byte) ch);
                out.write(ch);
            }

            out.close();

            PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

            if (ops.verify(p3.get(0))) {
                System.out.println("signature verified.");
            } else {
                System.out.println("signature verification failed.");
            }
        } else if (message instanceof PGPSignatureList) {
            PGPSignatureList list = (PGPSignatureList) message;

            PGPSignature sig = list.get(0);

            message = pgpFact.nextObject();

            if (message == null) {
                System.out.println("Message is null");
            } else if (message instanceof PGPLiteralData) {
                System.out.println("message je literal");
            } else {
                System.out.println("message je nesto drugo");
            }
        }

    }

    public static String bytesToAlphabeticString(byte[] bytes) {
        CharBuffer cb = ByteBuffer.wrap(bytes).asCharBuffer();
        return cb.toString();
    }

    /*private static void decryptFile(
            String inputFileName,
            String keyFileName,
            char[] passwd,
            String defaultFileName, String keyFileSign, boolean ok)
            throws IOException, NoSuchProviderException {
        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
        decryptFile(in, keyIn, passwd, defaultFileName, keyFileSign);
        keyIn.close();
        in.close();
    }*/
    /**
     * decrypt the passed in message stream
     */
    private static void decryptFile(
            String inputFileName,
            String keyFileName,
            char[] passwd,
            String defaultFileName, String keyFileSign)
            throws IOException, NoSuchProviderException {

        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
        InputStream inForSignOnly = in;
        in = PGPUtil.getDecoderStream(in);
        InputStream inSign = new BufferedInputStream(new FileInputStream(keyFileSign));
        inSign = PGPUtil.getDecoderStream(inSign);
        try {
            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
            PGPEncryptedDataList enc = null;

            Object o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
            } else {
                try {
                    o = pgpF.nextObject();
                } catch (IOException e) {

                }

                if (o != null && o instanceof PGPEncryptedDataList) {

                    enc = (PGPEncryptedDataList) o;

                } else {
                    System.out.println("ovde sam");
                    try {

                        FileInputStream in2 = new FileInputStream(inputFileName);
                        FileInputStream keyIn2 = new FileInputStream(keyFileSign);

                        verifyFile(in2, keyIn2);
                    } catch (Exception ex) {
                        Logger.getLogger(proba_enkripcija.class.getName()).log(Level.SEVERE, null, ex);
                    }

                    return;

                }
            }

            System.out.println("ovde nisam");
            //
            // find8 the secret key
            //
            Iterator it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

            while (sKey == null && it.hasNext()) {
                pbe = (PGPPublicKeyEncryptedData) it.next();
                System.out.println("pbe " + Long.toHexString(pbe.getKeyID()));
                sKey = UtilFile.findSecretKey(pgpSec, pbe.getKeyID(), passwd);
            }

            if (sKey == null) {
                throw new IllegalArgumentException("secret key for message not found.");
            }

            InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));

            JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);

            Object message = plainFact.nextObject();

            JcaPGPObjectFactory pgpFact = null;
            if (message instanceof PGPCompressedData) {

                System.out.println("Message is instance of compressed data!");
                PGPCompressedData cData = (PGPCompressedData) message;
                pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

                message = pgpFact.nextObject();
                Object z = pgpFact.nextObject();
                if (z != null) {
                    System.out.println("z nije null");
                } else {
                    System.out.println("z je null");
                }
            }

            String outFileName = null;
            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;

                outFileName = ld.getFileName();

                //System.out.println("file name: " + outFileName);
                if (outFileName.length() == 0) {
                    System.out.println("File name lenght is 0");
                    // outFileName = defaultFileName;
                }

                InputStream unc = ld.getInputStream();
                OutputStream fOut = new BufferedOutputStream(new FileOutputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys" + outFileName));

                Streams.pipeAll(unc, fOut);

                fOut.close();

            } else if (message instanceof PGPOnePassSignatureList) {
                PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) message;

                PGPOnePassSignature ops = p1.get(0);

                PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();

                InputStream dIn = p2.getInputStream();
                int ch;
                PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(inSign), new JcaKeyFingerprintCalculator());

                //System.out.println("p2 file name: " + p2.getFileName());
                outFileName = p2.getFileName();

                PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());
                FileOutputStream out = new FileOutputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys" + p2.getFileName());

                if (key == null) {
                    System.out.println("key je null");
                }
                ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

                while ((ch = dIn.read()) >= 0) {
                    ops.update((byte) ch);
                    out.write(ch);
                }

                out.close();

                PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

                if (ops.verify(p3.get(0))) {
                    System.out.println("signature verified.");
                } else {
                    System.out.println("signature verification failed.");
                }

                //throw new PGPException("encrypted message contains a signed message - not literal data.");
            } else {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isIntegrityProtected()) {
                if (!pbe.verify()) {
                    System.err.println("message failed integrity check");
                } else {
                    System.err.println("message integrity check passed");
                }
            } else {
                System.err.println("no message integrity check");
            }
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        } finally {
            keyIn.close();
            in.close();
        }

    }

    private static void decryptFile(String inputFileName, char[] passPhrase)
            throws IOException, NoSuchProviderException, PGPException {
        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        decryptFile(in, passPhrase);
        in.close();
    }

    private static void decryptFile(
            InputStream in,
            char[] passPhrase)
            throws IOException, NoSuchProviderException, PGPException {
        in = PGPUtil.getDecoderStream(in);

        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();

        //
        // the first object might be a PGP marker packet.
        //
        PGPPBEEncryptedData pbe = null;
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
            pbe = (PGPPBEEncryptedData) enc.get(0);
        } else {
            Object o1 = pgpF.nextObject();
            System.out.println("hej: " + o1.getClass());
            if (o1 instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
                pbe = (PGPPBEEncryptedData) enc.get(0);
            } else if (o1 instanceof PGPPBEEncryptedData) {
                pbe = (PGPPBEEncryptedData) o1;
            }
        }

        InputStream clear = pbe.getDataStream(new JcePBEDataDecryptorFactoryBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(passPhrase));

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);

        //
        // if we're trying to read a file generated by someone other than us
        // the data might not be compressed, so we check the return type from
        // the factory and behave accordingly.
        //
        o = pgpFact.nextObject();
        if (o instanceof PGPCompressedData) {
            PGPCompressedData cData = (PGPCompressedData) o;

            pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

            o = pgpFact.nextObject();
        }

        PGPLiteralData ld = (PGPLiteralData) o;
        InputStream unc = ld.getInputStream();

        OutputStream fOut = new BufferedOutputStream(new FileOutputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//" + ld.getFileName()));

        Streams.pipeAll(unc, fOut);

        fOut.close();

        if (pbe.isIntegrityProtected()) {
            if (!pbe.verify()) {
                System.err.println("message failed integrity check");
            } else {
                System.err.println("message integrity check passed");
            }
        } else {
            System.err.println("no message integrity check");
        }
    }

    public static boolean decrypt(String inputFileName, String publicKeyFileName, String outputFileName, String passphrase) throws Exception {
        FileInputStream in = new FileInputStream(inputFileName);
        FileInputStream keyIn = new FileInputStream(publicKeyFileName);
        FileOutputStream out = new FileOutputStream(outputFileName);
        UtilFile.decryptFile(in, out, keyIn, passphrase.toCharArray());
        in.close();
        out.close();
        keyIn.close();
        return true;
    }

    /*
    private static void verifyFile(
            InputStream in,
            InputStream keyIn)
            throws Exception {
        in = PGPUtil.getDecoderStream(in);

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);

        PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();

        pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

        PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) pgpFact.nextObject();

        PGPOnePassSignature ops = p1.get(0);

        PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();

        InputStream dIn = p2.getInputStream();
        int ch;
        PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

        System.out.println("p2 file name: " + p2.getFileName());
        PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());
        FileOutputStream out = new FileOutputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//" + p2.getFileName());

        ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

        while ((ch = dIn.read()) >= 0) {
            ops.update((byte) ch);
            out.write(ch);
        }

        out.close();

        PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

        if (ops.verify(p3.get(0))) {
            System.out.println("signature verified.");
        } else {
            System.out.println("signature verification failed.");
        }
    }*/
    private static void verifySignature(
            String fileName,
            String inputFileName,
            String keyFileName)
            throws GeneralSecurityException, IOException, PGPException {
        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));

        verifySignature(fileName, in, keyIn);

        keyIn.close();
        in.close();
    }

    /*
     * verify the signature in in against the file fileName.
     */
    private static void verifySignature(
            String fileName,
            InputStream in,
            InputStream keyIn)
            throws GeneralSecurityException, IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);
        PGPSignatureList p3;

        Object o = pgpFact.nextObject();
        if (o instanceof PGPCompressedData) {
            PGPCompressedData c1 = (PGPCompressedData) o;

            pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

            p3 = (PGPSignatureList) pgpFact.nextObject();
        } else {
            p3 = (PGPSignatureList) o;
        }

        PGPPublicKeyRingCollection pgpPubRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

        InputStream dIn = new BufferedInputStream(new FileInputStream(fileName));

        PGPSignature sig = p3.get(0);
        PGPPublicKey key = pgpPubRingCollection.getPublicKey(sig.getKeyID());

        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

        int ch;
        while ((ch = dIn.read()) >= 0) {
            sig.update((byte) ch);
        }

        dIn.close();

        if (sig.verify()) {
            System.out.println("signature verified.");
        } else {
            System.out.println("signature verification failed.");
        }
    }

    /* public static boolean signEncrypt(String outputFileName, String inputFileName, String publicKeyFileName, String secretKeyFileName, String pass) throws Exception {
        FileOutputStream out = new FileOutputStream(outputFileName);
        FileInputStream publicKeyIn = new FileInputStream(publicKeyFileName);
        FileInputStream secretKeyIn = new FileInputStream(secretKeyFileName);

        PGPPublicKey publicKey = UtilFile.readPublicKey(publicKeyIn);
        PGPSecretKey secretKey = UtilFile.readSecretKey(secretKeyIn);

        UtilFile.signEncryptFile(
                out,
                inputFileName,
                publicKey,
                secretKey,
                pass,
                true,
                true);

        out.close();
        publicKeyIn.close();
        secretKeyIn.close();

        return true;
    }*/
    private static void encryptFile(
            String outputFileName,
            String inputFileName,
            String encKeyFileName,
            String encKeyFileName2,
            boolean armor,
            boolean withIntegrityCheck)
            throws IOException, NoSuchProviderException, PGPException {
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));
        PGPPublicKey encKey = readPublicKey(encKeyFileName);
        PGPPublicKey encKey2 = readPublicKey(encKeyFileName2);
        encryptFile(out, inputFileName, encKey, encKey2, armor, withIntegrityCheck);
        out.close();
    }

    private static void encryptFile(
            OutputStream out,
            String fileName,
            PGPPublicKey encKey,
            PGPPublicKey encKey2,
            boolean armor,
            boolean withIntegrityCheck)
            throws IOException, NoSuchProviderException {
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        try {
            byte[] bytes = compressFile(fileName, CompressionAlgorithmTags.ZIP);

            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));

            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey2).setProvider("BC"));

            OutputStream cOut = encGen.open(out, bytes.length);

            cOut.write(bytes);
            cOut.close();

            if (armor) {
                out.close();
            }
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    private static void signFile(
            String fileName,
            InputStream keyIn,
            OutputStream out,
            char[] pass,
            boolean armor)
            throws IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException {
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        PGPSecretKey pgpSec = UtilFile.readSecretKey(keyIn);
        PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        Iterator it = pgpSec.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

            spGen.setSignerUserID(false, (String) it.next());
            sGen.setHashedSubpackets(spGen.generate());
        }

        PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(
                PGPCompressedData.ZIP);

        BCPGOutputStream bOut = new BCPGOutputStream(cGen.open(out));

        sGen.generateOnePassVersion(false).encode(bOut);

        File file = new File(fileName);
        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY, file);
        FileInputStream fIn = new FileInputStream(file);
        int ch;

        while ((ch = fIn.read()) >= 0) {
            lOut.write(ch);
            sGen.update((byte) ch);
        }

        lGen.close();

        sGen.generate().encode(bOut);

        cGen.close();

        if (armor) {
            out.close();
        }
        fIn.close();
        //lOut.close();
    }

    static byte[] compressFile(String fileName, int algorithm) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
        PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY,
                new File(fileName));
        comData.close();
        return bOut.toByteArray();
    }

    static PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //
        Iterator keyRingIter = pgpSec.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();

            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = (PGPSecretKey) keyIter.next();

                if (key.isSigningKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }

    static PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPPublicKey pubKey = readPublicKey(keyIn);
        keyIn.close();
        return pubKey;
    }

    /**
     * A simple routine that opens a key ring file and loads the first available
     * key suitable for encryption.
     *
     * @param input data stream containing the public key data
     * @return the first public key found.
     * @throws IOException
     * @throws PGPException
     */
    static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //
        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) keyIter.next();

                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    private static int readInputLine(ByteArrayOutputStream bOut, InputStream fIn)
            throws IOException {
        bOut.reset();

        int lookAhead = -1;
        int ch;

        while ((ch = fIn.read()) >= 0) {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        }

        return lookAhead;
    }

    private static int readInputLine(ByteArrayOutputStream bOut, int lookAhead, InputStream fIn)
            throws IOException {
        bOut.reset();

        int ch = lookAhead;

        do {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        } while ((ch = fIn.read()) >= 0);

        if (ch < 0) {
            lookAhead = -1;
        }

        return lookAhead;
    }

    private static int readPassedEOL(ByteArrayOutputStream bOut, int lastCh, InputStream fIn)
            throws IOException {
        int lookAhead = fIn.read();

        if (lastCh == '\r' && lookAhead == '\n') {
            bOut.write(lookAhead);
            lookAhead = fIn.read();
        }

        return lookAhead;
    }

    /*
     * verify a clear text signed file
     *//*
    private static void verifyFile(
            InputStream in,
            InputStream keyIn,
            String resultName)
            throws Exception {
        ArmoredInputStream aIn = new ArmoredInputStream(in);
        OutputStream out = new BufferedOutputStream(new FileOutputStream(resultName));

        //
        // write out signed section using the local line separator.
        // note: trailing white space needs to be removed from the end of
        // each line RFC 4880 Section 7.1
        //
        ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
        int lookAhead = readInputLine(lineOut, aIn);
        byte[] lineSep = getLineSeparator();

        if (lookAhead != -1 && aIn.isClearText()) {
            byte[] line = lineOut.toByteArray();
            out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
            out.write(lineSep);

            while (lookAhead != -1 && aIn.isClearText()) {
                lookAhead = readInputLine(lineOut, lookAhead, aIn);

                line = lineOut.toByteArray();
                out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
                out.write(lineSep);
            }
        } else {
            // a single line file
            if (lookAhead != -1) {
                byte[] line = lineOut.toByteArray();
                out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
                out.write(lineSep);
            }
        }

        out.close();

        PGPPublicKeyRingCollection pgpRings = new PGPPublicKeyRingCollection(keyIn, new JcaKeyFingerprintCalculator());

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(aIn);
        PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();
        PGPSignature sig = p3.get(0);

        PGPPublicKey publicKey = pgpRings.getPublicKey(sig.getKeyID());
        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);

        //
        // read the input, making sure we ignore the last newline.
        //
        InputStream sigIn = new BufferedInputStream(new FileInputStream(resultName));

        lookAhead = readInputLine(lineOut, sigIn);

        processLine(sig, lineOut.toByteArray());

        if (lookAhead != -1) {
            do {
                lookAhead = readInputLine(lineOut, lookAhead, sigIn);

                sig.update((byte) '\r');
                sig.update((byte) '\n');

                processLine(sig, lineOut.toByteArray());
            } while (lookAhead != -1);
        }

        sigIn.close();

        if (sig.verify()) {
            System.out.println("signature verified.");
        } else {
            System.out.println("signature verification failed.");
        }
    }*/

    private static byte[] getLineSeparator() {
        String nl = Strings.lineSeparator();
        byte[] nlBytes = new byte[nl.length()];

        for (int i = 0; i != nlBytes.length; i++) {
            nlBytes[i] = (byte) nl.charAt(i);
        }

        return nlBytes;
    }

    /*
     * create a clear text signed file.
     */
    private static void signFile(
            String fileName,
            InputStream keyIn,
            OutputStream out,
            char[] pass,
            String digestName)
            throws IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException {
        int digest;

        if (digestName.equals("SHA256")) {
            digest = PGPUtil.SHA256;
        } else if (digestName.equals("SHA384")) {
            digest = PGPUtil.SHA384;
        } else if (digestName.equals("SHA512")) {
            digest = PGPUtil.SHA512;
        } else if (digestName.equals("MD5")) {
            digest = PGPUtil.MD5;
        } else if (digestName.equals("RIPEMD160")) {
            digest = PGPUtil.RIPEMD160;
        } else {
            digest = PGPUtil.SHA1;
        }

        PGPSecretKey pgpSecKey = UtilFile.readSecretKey(keyIn);
        PGPPrivateKey pgpPrivKey = pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSecKey.getPublicKey().getAlgorithm(), digest).setProvider("BC"));
        PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

        sGen.init(PGPSignature.POSITIVE_CERTIFICATION, pgpPrivKey);

        Iterator it = pgpSecKey.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            spGen.setSignerUserID(false, (String) it.next());
            sGen.setHashedSubpackets(spGen.generate());
        }

        InputStream fIn = new BufferedInputStream(new FileInputStream(fileName));
        ArmoredOutputStream aOut = new ArmoredOutputStream(out);

        aOut.beginClearText(digest);

        //
        // note the last \n/\r/\r\n in the file is ignored
        //
        ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
        int lookAhead = readInputLine(lineOut, fIn);

        processLine(aOut, sGen, lineOut.toByteArray());

        if (lookAhead != -1) {
            do {
                lookAhead = readInputLine(lineOut, lookAhead, fIn);

                sGen.update((byte) '\r');
                sGen.update((byte) '\n');

                processLine(aOut, sGen, lineOut.toByteArray());
            } while (lookAhead != -1);
        }

        fIn.close();

        aOut.endClearText();

        BCPGOutputStream bOut = new BCPGOutputStream(aOut);

        sGen.generate().encode(bOut);

        aOut.close();
    }

    private static void processLine(PGPSignature sig, byte[] line)
            throws SignatureException, IOException {
        int length = getLengthWithoutWhiteSpace(line);
        if (length > 0) {
            sig.update(line, 0, length);
        }
    }

    private static void processLine(OutputStream aOut, PGPSignatureGenerator sGen, byte[] line)
            throws SignatureException, IOException {
        // note: trailing white space needs to be removed from the end of
        // each line for signature calculation RFC 4880 Section 7.1
        int length = getLengthWithoutWhiteSpace(line);
        if (length > 0) {
            sGen.update(line, 0, length);
        }

        aOut.write(line, 0, line.length);
    }

    private static int getLengthWithoutSeparatorOrTrailingWhitespace(byte[] line) {
        int end = line.length - 1;

        while (end >= 0 && isWhiteSpace(line[end])) {
            end--;
        }

        return end + 1;
    }

    private static boolean isLineEnding(byte b) {
        return b == '\r' || b == '\n';
    }

    private static int getLengthWithoutWhiteSpace(byte[] line) {
        int end = line.length - 1;

        while (end >= 0 && isWhiteSpace(line[end])) {
            end--;
        }

        return end + 1;
    }

    private static boolean isWhiteSpace(byte b) {
        return isLineEnding(b) || b == '\t' || b == ' ';
    }

}
