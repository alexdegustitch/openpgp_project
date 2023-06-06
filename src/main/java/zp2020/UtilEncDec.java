/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package zp2020;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.filechooser.FileSystemView;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
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
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
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
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import static zp2020.proba_enkripcija.readSecretKey;

/**
 *
 * @author Aleksandar
 */
public class UtilEncDec {

    public static void signFile(String fileName,
            String keyName,
            char[] pass,
            boolean armor)
            throws IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException {

        Security.addProvider(new BouncyCastleProvider());
        FileInputStream keyIn = new FileInputStream(keyName);
        File f = new File(fileName);

        try ( FileOutputStream out = new FileOutputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + f.getName() + ".asc")) {
            signFile(fileName, keyIn, out, pass, true);
        }
        keyIn.close();
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
            System.out.println("jedan next");
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
        keyIn.close();
        //lOut.close();
    }

    public static void encryptFile(
            String outputFileName,
            String inputFileName,
            List<String> encKeys,
            int alg,
            boolean armor,
            boolean withIntegrityCheck)
            throws IOException, NoSuchProviderException, PGPException {
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));
        List<PGPPublicKey> pgpKeys = new LinkedList<PGPPublicKey>();

        for (int i = 0; i < encKeys.size(); i++) {
            PGPPublicKey pg = readPublicKey(encKeys.get(i));
            pgpKeys.add(pg);
        }
        encryptFile(out, inputFileName, pgpKeys, alg, armor, withIntegrityCheck);
        out.close();
    }

    private static void encryptFile(
            OutputStream out,
            String fileName,
            List<PGPPublicKey> encKeys,
            int alg,
            boolean armor,
            boolean withIntegrityCheck)
            throws IOException, NoSuchProviderException {
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        try {
            byte[] bytes = compressFile(fileName, CompressionAlgorithmTags.ZIP);

            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(alg).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));

            for (int i = 0; i < encKeys.size(); i++) {
                encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKeys.get(i)).setProvider("BC"));
            }
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

    public static boolean signEncrypt(String outputFileName, String inputFileName, List<String> publicKeyFileNames, String secretKeyFileName, String pass, int alg) throws Exception {
        FileOutputStream out = new FileOutputStream(outputFileName);

        List<PGPPublicKey> publicKeys = new LinkedList<PGPPublicKey>();
        List<FileInputStream> publicKeysIn = new LinkedList<FileInputStream>();

        for (int i = 0; i < publicKeyFileNames.size(); i++) {
            FileInputStream publicKeyIn = new FileInputStream(publicKeyFileNames.get(i));
            publicKeysIn.add(publicKeyIn);
            publicKeys.add(UtilFile.readPublicKey(publicKeyIn));
        }

        FileInputStream secretKeyIn = new FileInputStream(secretKeyFileName);

        //PGPPublicKey publicKey = UtilFile.readPublicKey(publicKeyIn);
        PGPSecretKey secretKey = UtilFile.readSecretKey(secretKeyIn);

        UtilFile.signEncryptFile(
                out,
                inputFileName,
                publicKeys,
                secretKey,
                pass,
                alg,
                true,
                true);

        out.close();
        for (int i = 0; i < publicKeysIn.size(); i++) {
            publicKeysIn.get(i).close();
        }
        secretKeyIn.close();

        return true;
    }

    public static String decryptFile(
            String inputFileName, List<MySubKey> sub_keys, List<MyMasterKey> master_keys)
            throws IOException, NoSuchProviderException {

        String ext = FilenameUtils.getExtension(inputFileName); // returns "txt"

        if (!ext.equals("asc") && !ext.equals("sig") && !ext.equals("pgp") && !ext.equals("gpg")) {
            return "no_type";
        }
        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream keyIn = null;
        FileOutputStream out = null;//new BufferedInputStream(new FileInputStream(keyFileName));
        //InputStream inForSignOnly = in;
        in = PGPUtil.getDecoderStream(in);
        String res = "ok";
        //InputStream inSign = new BufferedInputStream(new FileInputStream(keyFileSign));
        //inSign = PGPUtil.getDecoderStream(inSign);
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
                    /* System.out.println("ovde sam");
                    try {

                        FileInputStream in2 = new FileInputStream(inputFileName);
                        FileInputStream keyIn2 = new FileInputStream(keyFileSign);

                        verifyFile(in2, keyIn2);
                    } catch (Exception ex) {
                        Logger.getLogger(proba_enkripcija.class.getName()).log(Level.SEVERE, null, ex);
                    }
                     */
                    return "sign";

                }
            }

            System.out.println("ovde nisam");
            //
            // find8 the secret key
            //
            Iterator it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;

            while (sKey == null && it.hasNext()) {
                pbe = (PGPPublicKeyEncryptedData) it.next();
                //System.out.println("pbe " + Long.toHexString(pbe.getKeyID()));

                File files = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys");
                File[] listFile = files.listFiles();

                keyIn = null;

                MySubKey sk = null;
                for (int i = 0; i < listFile.length; i++) {
                    System.out.println("pbe key ID " + Long.toHexString(pbe.getKeyID()));
                    sk = find_sub_key(sub_keys, Long.toHexString(pbe.getKeyID()));

                    if (sk != null) {
                        if (listFile[i].getAbsolutePath().contains(sk.getMaster_key_id() + "SECRET.asc")) {
                            keyIn = new BufferedInputStream(new FileInputStream(listFile[i].getAbsolutePath()));
                            break;
                        }
                    }
                }

                int num = 0;

                if (keyIn != null) {
                    PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                            PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());
                    while (sKey == null && num < 3) {
                        num++;

                        String passwd = "";
                        //passwd = JOptionPane.showInputDialog("Try " + num + "/3: \n Please input a passphrase for " + sk.getName() + "<" + sk.getEmail() + ">");

                        JPanel panel = new JPanel(new BorderLayout());
                        JLabel label = new JLabel("Please enter the passphrase for " + sk.getName() + "<" + sk.getEmail() + ">\n");
                        JPasswordField pass = new JPasswordField(10);
                        JPanel centerPanel = new JPanel(new GridLayout(2, 1));
                        centerPanel.add(label);
                        centerPanel.add(pass);
                        panel.add(BorderLayout.CENTER, centerPanel);

                        String[] options = new String[]{"OK", "Cancel"};
                        int option = JOptionPane.showOptionDialog(null, panel, "Try " + num + "/3:",
                                JOptionPane.NO_OPTION, JOptionPane.PLAIN_MESSAGE,
                                null, options, options[1]);
                        if (option == 0) // pressing OK button
                        {
                            passwd = pass.getText();
                        } else {
                            passwd = "";
                            num = 3;
                        }

                        try {
                            System.out.println("try pass " + passwd);
                            sKey = UtilFile.findSecretKey(pgpSec, pbe.getKeyID(), passwd.toCharArray());
                            System.out.println("i ovde try pass " + passwd);
                            if (sKey == null) {
                                System.out.println("SKEY JE NULL");
                            }

                        } catch (PGPException e) {
                            sKey = null;
                            System.out.println(" u catch-u sam");
                        }
                        System.out.println("ne hej");
                        if (sKey == null) {
                            System.out.println("sKey je null");
                        }

                    }
                }
            }

            if (sKey == null) {
                return "no_secret_key";
                //throw new IllegalArgumentException("secret key for message not found.");
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
            }

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;

                String outFileName = ld.getFileName();
                System.out.println("ld file name: " + outFileName);
                if (outFileName.length() == 0) {
                    File f = new File(inputFileName);
                    outFileName = f.getName();
                    outFileName = outFileName.substring(0, outFileName.length() - 4);
                }

                InputStream unc = ld.getInputStream();
                OutputStream fOut = new BufferedOutputStream(new FileOutputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + outFileName));

                Streams.pipeAll(unc, fOut);

                fOut.close();

            } else if (message instanceof PGPOnePassSignatureList) {
                PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) message;

                PGPOnePassSignature ops = p1.get(0);

                PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();

                InputStream dIn = p2.getInputStream();
                int ch;
                File files = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys");
                File[] listFile = files.listFiles();

                int i = 0;
                PGPPublicKey key = null;

                while (i < listFile.length && key == null) {

                    if (listFile[i].getAbsolutePath().contains("PUBLIC.asc")) {
                        System.out.println("ovde sam hoho ");
                        InputStream inSign = new BufferedInputStream(new FileInputStream(listFile[i].getAbsolutePath()));
                        inSign = PGPUtil.getDecoderStream(inSign);
                        PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(inSign), new JcaKeyFingerprintCalculator());
                        key = pgpRing.getPublicKey(ops.getKeyID());

                        if (key != null) {

                            MyMasterKey mk = find_master_key(master_keys, Long.toHexString(ops.getKeyID()));
                            if (mk != null) {
                                res = mk.getName() + "<" + mk.getEmail() + ">";
                            } else {
                                res = "no_public_key";
                            }
                        }

                    }
                    i++;
                }
                //System.out.println("p2 file name: " + p2.getFileName());

                if (key == null) {
                    System.out.println("key je null");
                    res = "no_public_key";
                } else {
                    ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);
                }

                File f = new File(inputFileName);

                System.out.println("p2: " + inputFileName);
                out = new FileOutputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + f.getName().substring(0, f.getName().length() - 4));

                System.out.println("out je: " + FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + f.getName().substring(0, f.getName().length() - 4));
                while ((ch = dIn.read()) >= 0) {
                    if (key != null) {
                        ops.update((byte) ch);
                    }
                    out.write(ch);
                }

                out.close();

                if (key != null) {
                    PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

                    if (ops.verify(p3.get(0))) {
                        System.out.println("signature verified.");
                    } else {
                        System.out.println("signature verification failed.");
                    }
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
            if (keyIn != null) {
                keyIn.close();
            }
            if (in != null) {
                in.close();
            }
            if (out != null) {
                out.close();
            }
        }

        return res;
    }

    private static MySubKey find_sub_key(List<MySubKey> sub_keys, String key) {
        System.out.println("key " + key);
        for (int i = 0; i < sub_keys.size(); i++) {
            System.out.println("sub key[" + i + "]" + " " + sub_keys.get(i).getKey_id());
            if (sub_keys.get(i).getKey_id().equals(key)) {
                return sub_keys.get(i);
            }
        }

        return null;
    }

    private static MyMasterKey find_master_key(List<MyMasterKey> master_keys, String key) {
        for (int i = 0; i < master_keys.size(); i++) {
            if (master_keys.get(i).getKey_id().equals(key)) {
                return master_keys.get(i);
            }
        }

        return null;
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

    static byte[] compressFile(String fileName, int algorithm) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
        PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY,
                new File(fileName));
        comData.close();
        return bOut.toByteArray();
    }

    public static String verifyFile(
            InputStream in, List<MyMasterKey> master_keys, String fileName)
            throws Exception {
        in = PGPUtil.getDecoderStream(in);

        String res = "ok";
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);

        Object message = pgpFact.nextObject();
        if (message instanceof PGPCompressedData) {
            PGPCompressedData c1 = (PGPCompressedData) message;

            if (c1 == null) {
                in.close();
                return "no_type";
            }

            pgpFact = new JcaPGPObjectFactory(c1.getDataStream());
            message = pgpFact.nextObject();

        }

        //pgpFact = new JcaPGPObjectFactory(c1.getDataStream());
        if (message instanceof PGPOnePassSignatureList) {
            PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) message;
            PGPOnePassSignature ops = p1.get(0);
            PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();

            InputStream dIn = p2.getInputStream();
            int ch;

            File files = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys");
            File[] listFile = files.listFiles();

            int i = 0;
            PGPPublicKey key = null;

            System.out.println("stigao sam ovde");
            while (i < listFile.length && key == null) {

                if (listFile[i].getAbsolutePath().contains("PUBLIC.asc")) {
                    InputStream inSign = new BufferedInputStream(new FileInputStream(listFile[i].getAbsolutePath()));

                    inSign = PGPUtil.getDecoderStream(inSign);
                    PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(inSign), new JcaKeyFingerprintCalculator());
                    key = pgpRing.getPublicKey(ops.getKeyID());

                    inSign.close();
                    if (key != null) {
                        MyMasterKey mk = find_master_key(master_keys, Long.toHexString(ops.getKeyID()));
                        if (mk != null) {
                            res = mk.getName() + "<" + mk.getEmail() + ">";
                        } else {
                            res = "no_public_key";
                        }
                    }

                }
                i++;
            }
            System.out.println("ovde nisam stigao");
            //System.out.println("p2 file name: " + p2.getFileName());

            //PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());
            //PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());
            File f = new File(p2.getFileName());

            FileOutputStream out = new FileOutputStream(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + f.getName());

            if (key != null) {
                ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);
            } else {
                res = "no_public_key";
            }

            while ((ch = dIn.read()) >= 0) {
                if (key != null) {
                    ops.update((byte) ch);
                }
                out.write(ch);
            }

            out.close();
            dIn.close();

            if (key != null) {
                PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

                if (ops.verify(p3.get(0))) {
                    System.out.println("signature verified.");
                } else {
                    System.out.println("signature verification failed.");
                }
            }
        } else {

            PGPSignatureList p3;

            if (message instanceof PGPCompressedData) {
                PGPCompressedData c1 = (PGPCompressedData) message;

                pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

                p3 = (PGPSignatureList) pgpFact.nextObject();
            } else {
                p3 = (PGPSignatureList) message;
            }

            PGPSignature sig = p3.get(0);

            //PGPPublicKeyRingCollection pgpPubRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());
            InputStream dIn = new BufferedInputStream(new FileInputStream(fileName));

            File files = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys");
            File[] listFile = files.listFiles();

            int i = 0;
            PGPPublicKey key = null;

            System.out.println("stigao sam ovde");
            while (i < listFile.length && key == null) {

                if (listFile[i].getAbsolutePath().contains("PUBLIC.asc")) {
                    InputStream inSign = new BufferedInputStream(new FileInputStream(listFile[i].getAbsolutePath()));

                    inSign = PGPUtil.getDecoderStream(inSign);
                    PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(inSign), new JcaKeyFingerprintCalculator());
                    key = pgpRing.getPublicKey(sig.getKeyID());
                    inSign.close();
                    if (key != null) {

                        MyMasterKey mk = find_master_key(master_keys, Long.toHexString(sig.getKeyID()));
                        if (mk != null) {
                            res = "SIGNATURE" + mk.getName() + "<" + mk.getEmail() + ">";
                        } else {
                            res = "SIGNATURE_no_public_key";
                        }
                    }

                }
                i++;
            }

            if (key != null) {
                sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);
            } else {
                res = "SIGNATURE_no_public_key";
            }

            //PGPPublicKey key = pgpPubRingCollection.getPublicKey(sig.getKeyID());
            //sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);
            int ch;
            while ((ch = dIn.read()) >= 0) {
                if (key != null) {
                    sig.update((byte) ch);
                }

            }

            dIn.close();

            if (key != null) {
                if (sig.verify()) {
                    System.out.println("signature verified.");
                } else {
                    System.out.println("signature verification failed.");
                }
            }
        }

        return res;

    }

}
