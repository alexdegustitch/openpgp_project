package zp2020;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import static javax.management.Query.lt;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;

import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
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
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

class UtilFile {

    private static final int BUFFER_SIZE = 1 << 16; // should always be power of 2
    private static final int KEY_FLAGS = 27;
    private static final int[] MASTER_KEY_CERTIFICATION_TYPES = new int[]{PGPSignature.POSITIVE_CERTIFICATION, PGPSignature.CASUAL_CERTIFICATION, PGPSignature.NO_CERTIFICATION, PGPSignature.DEFAULT_CERTIFICATION};

    private static PGPPrivateKey findSecretKey(InputStream keyIn, long keyID, char[] pass)
            throws IOException, PGPException, NoSuchProviderException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }

        return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
    }

    public static void decryptFile(InputStream in, OutputStream out, InputStream keyIn, char[] passwd)
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);

        PGPObjectFactory pgpF = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
        PGPEncryptedDataList enc;

        Object o = pgpF.nextObject();
        //
        // the first object might be a PGP marker packet.
        //
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        //
        // find the secret key
        //
        Iterator it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;

        while (sKey == null && it.hasNext()) {
            pbe = (PGPPublicKeyEncryptedData) it.next();

            sKey = findSecretKey(keyIn, pbe.getKeyID(), passwd);
        }

        if (sKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        InputStream clear = pbe.getDataStream((PublicKeyDataDecryptorFactory) new JcePBEDataDecryptorFactoryBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(passwd));

        PGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);

        Object message = plainFact.nextObject();

        if (message instanceof PGPCompressedData) {
            PGPCompressedData cData = (PGPCompressedData) message;
            PGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());

            message = pgpFact.nextObject();
        }

        if (message instanceof PGPLiteralData) {
            PGPLiteralData ld = (PGPLiteralData) message;

            InputStream unc = ld.getInputStream();
            int ch;

            while ((ch = unc.read()) >= 0) {
                out.write(ch);
            }
        } else if (message instanceof PGPOnePassSignatureList) {
            throw new PGPException("Encrypted message contains a signed message - not literal data.");
        } else {
            throw new PGPException("Message is not a simple encrypted file - type unknown.");
        }

        if (pbe.isIntegrityProtected()) {
            if (!pbe.verify()) {
                throw new PGPException("Message failed integrity check");
            }
        }
    }

    static byte[] compressFile(String fileName, int algorithm) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
        PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY,
                new File(fileName));
        comData.close();
        return bOut.toByteArray();
    }

    /**
     * Search a secret key ring collection for a secret key corresponding to
     * keyID if it exists.
     *
     * @param pgpSec a secret key ring collection.
     * @param keyID keyID we want.
     * @param pass passphrase to decrypt secret key with.
     * @return the private key.
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
            throws PGPException, NoSuchProviderException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }

        return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
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

    static PGPSecretKey readSecretKey(String fileName) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPSecretKey secKey = readSecretKey(keyIn);
        keyIn.close();
        return secKey;
    }

    /**
     * A simple routine that opens a key ring file and loads the first available
     * key suitable for signature generation.
     *
     * @param input stream to read the secret key ring collection from.
     * @return a secret key.
     * @throws IOException on a problem with using the input stream.
     * @throws PGPException if there is an issue parsing the input stream.
     */
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

    private static boolean hasKeyFlags(PGPPublicKey encKey, int keyUsage) {
        if (encKey.isMasterKey()) {
            for (int i = 0; i != UtilFile.MASTER_KEY_CERTIFICATION_TYPES.length; i++) {
                for (Iterator eIt = encKey.getSignaturesOfType(UtilFile.MASTER_KEY_CERTIFICATION_TYPES[i]); eIt.hasNext();) {
                    PGPSignature sig = (PGPSignature) eIt.next();
                    if (!isMatchingUsage(sig, keyUsage)) {
                        return false;
                    }
                }
            }
        } else {
            for (Iterator eIt = encKey.getSignaturesOfType(PGPSignature.SUBKEY_BINDING); eIt.hasNext();) {
                PGPSignature sig = (PGPSignature) eIt.next();
                if (!isMatchingUsage(sig, keyUsage)) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean isMatchingUsage(PGPSignature sig, int keyUsage) {
        if (sig.hasSubpackets()) {
            PGPSignatureSubpacketVector sv = sig.getHashedSubPackets();
            if (sv.hasSubpacket(UtilFile.KEY_FLAGS)) {
                if ((sv.getKeyFlags() & keyUsage) == 0) {
                    return false;
                }
            }
        }
        return true;
    }

    public static void signEncryptFile(
            OutputStream out,
            String fileName,
            List<PGPPublicKey> publicKeys,
            PGPSecretKey secretKey,
            String password,
            int alg,
            boolean armor,
            boolean withIntegrityCheck) throws Exception {

        // Initialize Bouncy Castle security provider
        Security.addProvider(new BouncyCastleProvider());

        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        // Initialize encrypted data generator
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(alg).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));

        for (int i = 0; i < publicKeys.size(); i++) {
            encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKeys.get(i)).setProvider("BC"));
        }
        
        OutputStream encryptedOut = encryptedDataGenerator.open(out, new byte[UtilFile.BUFFER_SIZE]);

        // Initialize compressed data generator
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        OutputStream compressedOut = compressedDataGenerator.open(encryptedOut, new byte[UtilFile.BUFFER_SIZE]);

        // Initialize signature generator
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password.toCharArray()));

        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

        boolean firstTime = true;
        Iterator it = secretKey.getPublicKey().getUserIDs();
        while (it.hasNext() && firstTime) {
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, (String) it.next());
            signatureGenerator.setHashedSubpackets(spGen.generate());
            // Exit the loop after the first iteration
            firstTime = false;
        }
        signatureGenerator.generateOnePassVersion(false).encode(compressedOut);

        // Initialize literal data generator
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream literalOut = literalDataGenerator.open(
                compressedOut,
                PGPLiteralData.BINARY,
                fileName,
                new Date(),
                new byte[UtilFile.BUFFER_SIZE]);

        // Main loop - read the "in" stream, compress, encrypt and write to the "out" stream
        FileInputStream in = new FileInputStream(fileName);
        byte[] buf = new byte[UtilFile.BUFFER_SIZE];
        int len;
        while ((len = in.read(buf)) > 0) {
            literalOut.write(buf, 0, len);
            signatureGenerator.update(buf, 0, len);
        }

        in.close();
        literalDataGenerator.close();
        // Generate the signature, compress, encrypt and write to the "out" stream
        signatureGenerator.generate().encode(compressedOut);
        compressedDataGenerator.close();
        encryptedDataGenerator.close();
        if (armor) {
            out.close();
        }
    }
}
