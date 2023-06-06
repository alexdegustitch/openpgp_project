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
import java.io.InputStream;
import java.util.Base64;
import java.util.Date;
import java.util.Iterator;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.CRC32;
import java.util.zip.Checksum;
import javax.swing.filechooser.FileSystemView;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import org.bouncycastle.bcpg.CRC24;
import org.bouncycastle.crypto.tls.TlsExtensionsUtils;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

/**
 *
 * @author Aleksandar
 */
public class proba_new {

    public static long to_crc(byte[] data, int len) {
        long crc = 0xB704CEL;

        for (int j = 0; j < len; j++) {
            crc ^= data[j] << 16;
            for (int i = 0; i < 8; i++) {
                crc <<= 1;
                if ((crc & 0x1000000) != 0) {
                    crc ^= 0x1864CFBL;
                }
            }
        }

        return crc & 0xFFFFFFL;
    }

    public static void main(String[] args) throws DecoderException {

        InputStream in = null;
        try {
            File file = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp/stic_najjaci-546abf38876f3cfbSECRET.asc");
            in = new FileInputStream(file);
            PGPSecretKey pgpKey = readSecretKey(in);

         
            
            

        } catch (FileNotFoundException ex) {
            Logger.getLogger(proba_new.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | PGPException ex) {
            Logger.getLogger(proba_new.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                in.close();
            } catch (IOException ex) {
                Logger.getLogger(proba_new.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
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
}
