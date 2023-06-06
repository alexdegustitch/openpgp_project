package zp2020;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileSystemView;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.xml.bind.DatatypeConverter;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * Utility class for chapter 4 examples
 */
public class Utils {

    private static String name;
    private static String email;
    private static String passphrase;

    private static int dsa_key = 1024;
    private static int elgamal_key = 1024;

    private static JTextField name_text, email_text;
    private static JPasswordField pass_text, pass_confirm_text;

    private static JButton ok_pass_button;

    private static List<MyMasterKey> master_keys = new LinkedList<>();
    private static List<MySubKey> sub_keys = new LinkedList<>();

    private static final Base64 base64 = new Base64();

    private static JTable central_table;
    private static List<Object[]> data;

    private static JFileChooser jfc;
    private static JFileChooser sendMessageFile;
    private static JFileChooser exportPublicKeyFile;
    private static JFileChooser exportPrivateKeyFile;
    private static JFileChooser receiveMessageFile;
    private static JFileChooser saveMessageFile;
    private static JFileChooser saveFileFile;
    private static File fileName = null;

    public static JFrame get_frame() {
        JFrame f = new JFrame();

        JPanel jp = new JPanel(new BorderLayout());
        //f.setSize(500, 500);
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize().getSize();
        //System.out.println("h: " + screenSize.height + ", w: " + screenSize.width);

        f.setBounds(screenSize.width / 2 - 300, screenSize.height / 2 - 300, 800, 600);

        JPanel north_panel = new JPanel(new FlowLayout());

        JButton generate_key_button = new JButton("Generate key pair");
        JButton import_key_button = new JButton("Import public key");
        JButton import_private_key_button = new JButton("Import private key");
        JButton send_message_button = new JButton("Send message");
        JButton receive_message_button = new JButton("Receive message");
        JButton list_files = new JButton("List files");

        import_key_button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFrame import_frame = get_import_public_key_frame(f, screenSize);
            }
        });

        import_private_key_button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFrame import_frame = get_import_private_key_frame(f, screenSize);
            }
        });

        generate_key_button.addActionListener(new ActionListener() {
            /*File zp_folder = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp");
                    if(!zp_folder.exists()){
                        home.createNewFile();
                    }
                    System.out.println(home.getAbsolutePath());*/
            @Override
            public void actionPerformed(ActionEvent e) {
                JFrame generate_key_frame = Utils.get_generate_key_window(f, screenSize);

            }

        });

        send_message_button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFrame send_message_frame = get_send_message_frame(f, screenSize);
            }
        });

        receive_message_button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFrame receive_message_frame = get_receive_message_frame(f, screenSize);
            }
        });

        list_files.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                File f = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys");

                File[] files = f.listFiles();
                for (int i = 0; i < files.length; i++) {
                    System.out.println("FILE: " + files[i].getAbsolutePath());
                }
            }
        });

        north_panel.add(generate_key_button);
        north_panel.add(import_key_button);
        north_panel.add(import_private_key_button);
        north_panel.add(send_message_button);
        north_panel.add(receive_message_button);
        north_panel.add(list_files);

        jp.add(north_panel, BorderLayout.NORTH);

        JPanel center_panel = new JPanel(new BorderLayout());

        central_table = get_key_rings(f, screenSize);

        central_table.setFont(new Font(null, Font.PLAIN, 14));
        DefaultTableCellRenderer r = new DefaultTableCellRenderer() {
            Font font = new Font(null, Font.BOLD, 14);

            @Override
            public Component getTableCellRendererComponent(JTable table,
                    Object value, boolean isSelected, boolean hasFocus,
                    int row, int column) {
                super.getTableCellRendererComponent(table, value, isSelected, hasFocus,
                        row, column);
                if (master_keys.get(row).isPr_key()) {
                    setFont(font);
                }
                return this;
            }

        };

        central_table.getColumnModel().getColumn(0).setCellRenderer(r);
        central_table.getColumnModel().getColumn(1).setCellRenderer(r);
        central_table.getColumnModel().getColumn(2).setCellRenderer(r);
        central_table.getColumnModel().getColumn(3).setCellRenderer(r);

        JScrollPane scrollPane = new JScrollPane(central_table);
        central_table.setFillsViewportHeight(true);

        center_panel.add(scrollPane, BorderLayout.CENTER);

        jp.add(center_panel, BorderLayout.CENTER);

        f.getContentPane().add(jp);
        f.setVisible(true);

        f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        return f;
    }

    public static JFrame get_generate_key_window(JFrame f, Dimension screenSize) {

        dsa_key = 1024;
        elgamal_key = 1024;

        JFrame generate_key_frame = new JFrame();
        f.setEnabled(false);
        generate_key_frame.setResizable(false);

        generate_key_frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                f.setEnabled(true);
            }
        });

        //generate_key_frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        generate_key_frame.setBounds(screenSize.width / 2 - 200, screenSize.height / 2 - 100, 400, 200);

        //izgled
        JPanel jp = new JPanel(new BorderLayout());

        JLabel name_label = new JLabel("Name");
        JLabel email_label = new JLabel("E-mail");

        name_text = new JTextField();
        name_text.setFont(new Font(null, Font.ROMAN_BASELINE, 20));
        email_text = new JTextField();
        email_text.setFont(new Font(null, Font.ROMAN_BASELINE, 20));
        //jp.setFont(new Font("Verdana", Font.PLAIN, 20));

        JPanel form_panel = new JPanel(new GridLayout(3, 2));
        form_panel.add(name_label);
        form_panel.add(name_text);
        form_panel.add(email_label);
        form_panel.add(email_text);

        JButton next_button = new JButton("Next");
        next_button.setEnabled(false);

        name_text.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                warn();
            }

            public void warn() {
                //System.out.println("hej");
                if (name_text.getText().length() >= 3 && email_text.getText().length() >= 5) {
                    next_button.setEnabled(true);
                } else {
                    next_button.setEnabled(false);
                }
            }
        });
        email_text.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                warn();
            }

            public void warn() {
                //System.out.println("hej");
                if (name_text.getText().length() >= 3 && email_text.getText().length() >= 5) {
                    next_button.setEnabled(true);
                } else {
                    next_button.setEnabled(false);
                }
            }
        });

        jp.add(form_panel, BorderLayout.CENTER);

        String[] dsa_keys = {"1024bits", "2048bits"};
        String[] elgamal_keys = {"1024bits", "2048bits", "4096bits"};

        JComboBox dsa_alg = new JComboBox(dsa_keys);
        JComboBox elgamal_alg = new JComboBox(elgamal_keys);

        dsa_alg.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if (e.getStateChange() == ItemEvent.SELECTED) {
                    dsa_key = Integer.parseInt((String) e.getItem().toString().substring(0, 4));
                    //System.out.println("dsa key: " + dsa_key);
                }
            }
        });

        elgamal_alg.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if (e.getStateChange() == ItemEvent.SELECTED) {
                    elgamal_key = Integer.parseInt((String) e.getItem().toString().substring(0, 4));
                    //System.out.println("elgamal key: " + elgamal_key);
                }
            }
        });

        JPanel dsa_panel = new JPanel(new FlowLayout());
        JPanel elgamal_panel = new JPanel(new FlowLayout());

        JLabel dsa_label = new JLabel("DSA key: ");
        JLabel elgamal_label = new JLabel("ElGamal key: ");

        dsa_panel.add(dsa_label);
        dsa_panel.add(dsa_alg);

        elgamal_panel.add(elgamal_label);
        elgamal_panel.add(elgamal_alg);

        form_panel.add(dsa_panel);
        form_panel.add(elgamal_panel);

        next_button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                name = name_text.getText();
                email = email_text.getText();

                JFrame pass_frame = Utils.get_pass_frame(generate_key_frame, screenSize, f);

            }
        });
        jp.add(next_button, BorderLayout.SOUTH);

        generate_key_frame.setContentPane(jp);
        generate_key_frame.setVisible(true);

        return generate_key_frame;
    }

    public static JFrame get_pass_frame(JFrame f, Dimension screenSize, JFrame parent_frame) {
        JFrame pass_frame = new JFrame();

        f.setEnabled(false);

        pass_frame.setResizable(false);

        pass_frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                f.setEnabled(true);
            }
        });

        //generate_key_frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        pass_frame.setBounds(screenSize.width / 2 - 150, screenSize.height / 2 - 50, 250, 150);

        JLabel pass_label = new JLabel("Passphrase: ");
        pass_text = new JPasswordField();

        JLabel pass_confirm_label = new JLabel("Repeat: ");
        pass_confirm_text = new JPasswordField();

        ok_pass_button = new JButton("OK");
        ok_pass_button.setEnabled(false);

        ok_pass_button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                //f.setVisible(true);
                f.dispose();
                pass_frame.dispose();
                parent_frame.setEnabled(true);
                parent_frame.setVisible(true);

                add_key();

            }
        });

        pass_text.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                warn();
            }

            public void warn() {
                //System.out.println("hej");
                if (pass_text.getText().length() > 0 && pass_text.getText().equals(pass_confirm_text.getText())) {
                    ok_pass_button.setEnabled(true);
                } else {
                    ok_pass_button.setEnabled(false);
                }
            }
        });

        pass_confirm_text.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                warn();
            }

            public void warn() {
                //System.out.println("hej");
                if (pass_text.getText().length() > 0 && pass_text.getText().equals(pass_confirm_text.getText())) {
                    ok_pass_button.setEnabled(true);
                } else {
                    ok_pass_button.setEnabled(false);
                }
            }
        });

        JPanel center = new JPanel(new GridLayout(2, 2));
        center.add(pass_label);
        center.add(pass_text);

        center.add(pass_confirm_label);
        center.add(pass_confirm_text);

        JPanel jp = new JPanel(new BorderLayout());
        jp.add(center, BorderLayout.CENTER);

        jp.add(ok_pass_button, BorderLayout.SOUTH);

        pass_frame.setContentPane(jp);

        pass_frame.setVisible(true);
        return pass_frame;
    }

    private static void add_key() {
        try {
            Security.addProvider(new BouncyCastleProvider());

            passphrase = pass_text.getText();

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA", "BC");
            keyPairGenerator.initialize(dsa_key);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            DSAPrivateKey privateKey_dsa = (DSAPrivateKey) keyPair.getPrivate();
            DSAPublicKey publicKey_dsa = (DSAPublicKey) keyPair.getPublic();

            MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            byte[] hashedString = messageDigest.digest(passphrase.getBytes());

            //System.out.println(hashedString.length);
            byte[] hash = new byte[16];
            for (int i = 0; i < hash.length; i++) {
                hash[i] = hashedString[i];
            }
            SecretKey originalKey = new SecretKeySpec(hash, 0, hash.length, "CAST5");

            Cipher c = Cipher.getInstance("CAST5", "BC");
            c.init(Cipher.ENCRYPT_MODE, originalKey);

            byte[] cipher_text_dsa = c.doFinal(privateKey_dsa.getEncoded());

            //ovo cuvam u key ringu
            KeyPairGenerator elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
            BigInteger g = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
            BigInteger p = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

            DHParameterSpec elParams = new DHParameterSpec(p, g);

            //elgKpg.initialize(elParams);
            elgKpg.initialize(elgamal_key);

            //System.out.println("elgamal key size: " + elgamal_key);
            //
            // this is quicker because we are using pregenerated parameters.
            //
            KeyPair elgKp = elgKpg.generateKeyPair();
            //System.out.println("ovde isto radi");
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

            LocalDate now = LocalDate.now();

            JcaPGPKeyConverter conv = new JcaPGPKeyConverter();

            Date d = java.util.Date.from(now.atStartOfDay()
                    .atZone(ZoneId.systemDefault())
                    .toInstant());

            System.out.println("ok je");
            PGPPublicKey pk = conv.getPGPPublicKey(PublicKeyAlgorithmTags.DSA, publicKey_dsa, d);

            PGPPrivateKey private_key_basic = conv.getPGPPrivateKey(pk, privateKey_dsa);

            /*System.out.println("PRIVATE BASIC: " + UtilHex.toHex(private_key_basic.getPrivateKeyDataPacket().getEncoded()));
            System.out.println("PRIVATE BASIC PUBLIC GET CONTENTS: " + UtilHex.toHex(private_key_basic.getPublicKeyPacket().getEncodedContents()));
            System.out.println("            PRIVATE BASIC PUBLIC : " + UtilHex.toHex(private_key_basic.getPublicKeyPacket().getEncoded()));*/
            //System.out.println("nije ok");
            //byte[] key_id = Fingerprint.calculateFingerprint(publicKey_dsa.getEncoded());
            byte[] key_id = pk.getFingerprint();
            //byte[] key_id = publicKey_dsa.getEncoded();
            int index = key_id.length;

            byte[] res = new byte[8];
            int i = 0;
            while (i < 8) {
                i++;
                index--;
                res[8 - i] = key_id[index];
            }

            StringBuilder sb = new StringBuilder();
            byte[] res_old = res;

            String cipher_key = base64.encodeToString(cipher_text_dsa);
            //dsa master key
            sb.append(now.toString()).append(" ");
            sb.append(name).append("<").append(email).append("> endname ");
            sb.append(UtilHex.toHex(res)).append(" ");
            sb.append(UtilHex.toHex(publicKey_dsa.getEncoded())).append(" ");
            sb.append("DSA ");
            sb.append(cipher_key).append(" \n");

            MyMasterKey mk = new MyMasterKey();
            mk.setEmail(email);
            mk.setKey_id(UtilHex.toHex(res));
            mk.setName(name);
            mk.setPrivate_key(cipher_key);
            mk.setType("DSA");
            mk.setValid_from(now.toString());
            mk.setPublic_key(UtilHex.toHex(publicKey_dsa.getEncoded()));
            mk.setPr_key(true);
            master_keys.add(mk);

            //key_id = Fingerprint.calculateFingerprint(publicKey_elgamal.getEncoded());
            conv = new JcaPGPKeyConverter();

            PGPPublicKey pk_elg = conv.getPGPPublicKey(PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, publicKey_elgamal, d);

            key_id = pk_elg.getFingerprint();
            index = key_id.length;

            res = new byte[8];
            i = 0;
            while (i < 8) {
                i++;
                index--;
                res[8 - i] = key_id[index];
            }

            X509EncodedKeySpec spec = new X509EncodedKeySpec(DatatypeConverter.parseHexBinary(UtilHex.toHex(publicKey_dsa.getEncoded())));
            KeyFactory kf = KeyFactory.getInstance("DSA");

            PublicKey k_pub = kf.generatePublic(spec);

            //System.out.println("public key real: " + UtilHex.toHex(publicKey_dsa.getEncoded()));
            //System.out.println("public key: " + k_pub.getAlgorithm() + ", " + UtilHex.toHex(k_pub.getEncoded()));
            //elgamal subkey
            cipher_key = base64.encodeToString(cipher_text_elgamal);
            sb.append(now.toString()).append(" ");
            sb.append(name).append("<").append(email).append("> endname ");
            sb.append(UtilHex.toHex(res)).append(" ");
            sb.append(UtilHex.toHex(publicKey_elgamal.getEncoded())).append(" ");
            sb.append("ELGAMAL ");
            sb.append(cipher_key).append(" ");
            sb.append(UtilHex.toHex(res_old)).append(" \n");

            MySubKey sk = new MySubKey();
            sk.setEmail(email);
            sk.setKey_id(UtilHex.toHex(res));
            sk.setName(name);
            sk.setPrivate_key(cipher_key);
            sk.setType("ELGAMAL");
            sk.setValid_from(now.toString());
            sk.setMaster_key_id(UtilHex.toHex(res_old));
            sk.setPublic_key(UtilHex.toHex(publicKey_elgamal.getEncoded()));
            sub_keys.add(sk);

            //PGPPublicKey pk = (PGPPublicKey) publicKey_dsa;
            //System.out.println("PAZNJAAAAAAAA: " + pk.getKeyID());
            /*System.out.println("PRIVATE KEY DSA: " + UtilHex.toHex(privateKey_dsa.getEncoded()));
            System.out.println("PRIVATE KEY ELG: " + UtilHex.toHex(privateKey_elgamal.getEncoded()));
            System.out.println("PRIVATE KEY DSA ENCODED: " + UtilHex.toHex(cipher_text_dsa));
            System.out.println("PRIVATE KEY ELG ENCODED: " + UtilHex.toHex(cipher_text_elgamal));*/
            try {

                Files.write(Paths.get(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//private_keyring.txt"), sb.toString().getBytes(), StandardOpenOption.APPEND);
                Object[] row = new Object[4];
                row[0] = name;
                row[1] = email;
                row[2] = now.toString();

                String key_id_hex = UtilHex.toHex(res_old).toUpperCase();
                row[3] = key_id_hex.substring(0, 4) + " " + key_id_hex.substring(4, 8) + " " + key_id_hex.substring(8, 12) + " " + key_id_hex.substring(12, 16);

                DefaultTableModel model = (DefaultTableModel) central_table.getModel();
                model.addRow(row);
                data.add(row);

                UtilExpImp.generate_key_pair(mk, sk, passphrase);

            } catch (IOException e) {
                //exception handling left as an exercise for the reader
            } finally {

            }

        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
            //exception handling left as an exercise for the reader
        } catch (PGPException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    private static JTable get_key_rings(JFrame frame, Dimension screenSize) {
        String[] columnNames = {"Name",
            "E-Mail",
            "Valid From",
            "Key ID"};

        ArrayList<Object[]> list = new ArrayList<>();

        File dir = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//private_keyring.txt");

        if (dir.exists() && dir.isFile()) {
            try {
                //data = new Object[directoryListing.length][4];
                Object[] row = new Object[4];
                Scanner in = new Scanner(new InputStreamReader(new FileInputStream(dir.getAbsolutePath()), StandardCharsets.UTF_8));
                int i = 0;
                boolean master = true;
                while (in.hasNext()) {

                    if (master) {
                        MyMasterKey mk = new MyMasterKey();

                        mk.setValid_from(in.next());
                        StringBuilder sb = new StringBuilder();
                        String next = in.next();
                        while (!next.equals("endname")) {
                            sb.append(next + " ");
                            next = in.next();
                        }
                        String name_and_email = sb.toString();
                        System.out.println("name :" + name_and_email);
                        String[] splitted = name_and_email.split("<");
                        mk.setName(splitted[0]);
                        mk.setEmail(splitted[1].substring(0, splitted[1].length() - 2));
                        mk.setKey_id(in.next());
                        mk.setPublic_key(in.next());
                        mk.setType(in.next());
                        mk.setPrivate_key(in.next());
                        mk.setPr_key(true);

                        row[0] = mk.getName();
                        row[1] = mk.getEmail();
                        row[2] = mk.getValid_from();
                        String key_id = mk.getKey_id().toUpperCase();
                        row[3] = key_id.substring(0, 4) + " " + key_id.substring(4, 8) + " " + key_id.substring(8, 12) + " " + key_id.substring(12, 16);

                        list.add(row);
                        row = new Object[4];

                        master_keys.add(mk);

                        master = false;
                    } else {

                        MySubKey sk = new MySubKey();

                        sk.setValid_from(in.next());
                        StringBuilder sb = new StringBuilder();
                        String next = in.next();
                        while (!next.equals("endname")) {
                            sb.append(next + " ");
                            next = in.next();
                        }
                        String name_and_email = sb.toString();
                        System.out.println("name email: " + name_and_email);
                        String[] splitted = name_and_email.split("<");
                        sk.setName(splitted[0]);
                        sk.setEmail(splitted[1].substring(0, splitted[1].length() - 2));
                        sk.setKey_id(in.next());
                        sk.setPublic_key(in.next());
                        sk.setType(in.next());
                        sk.setPrivate_key(in.next());
                        sk.setMaster_key_id(in.next());

                        sub_keys.add(sk);

                        master = true;
                    }

                }
                in.close();
            } catch (FileNotFoundException ex) {
                Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
            }

        }

        File dir_pub = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//public_keyring.txt");

        if (dir_pub.exists() && dir_pub.isFile()) {
            try {
                //data = new Object[directoryListing.length][4];
                Object[] row = new Object[4];
                Scanner in = new Scanner(new InputStreamReader(new FileInputStream(dir_pub.getAbsolutePath()), StandardCharsets.UTF_8));
                int i = 0;
                boolean master = true;
                while (in.hasNext()) {

                    if (master) {
                        MyMasterKey mk = new MyMasterKey();

                        mk.setValid_from(in.next());
                        StringBuilder sb = new StringBuilder();
                        String next = in.next();
                        while (!next.equals("endname")) {
                            sb.append(next + " ");
                            next = in.next();
                        }
                        String name_and_email = sb.toString();
                        System.out.println("name :" + name_and_email);
                        String[] splitted = name_and_email.split("<");
                        mk.setName(splitted[0]);
                        mk.setEmail(splitted[1].substring(0, splitted[1].length() - 2));
                        mk.setKey_id(in.next());
                        mk.setPublic_key(in.next());
                        mk.setType(in.next());

                        mk.setPr_key(false);

                        row[0] = mk.getName();
                        row[1] = mk.getEmail();
                        row[2] = mk.getValid_from();
                        String key_id = mk.getKey_id().toUpperCase();
                        row[3] = key_id.substring(0, 4) + " " + key_id.substring(4, 8) + " " + key_id.substring(8, 12) + " " + key_id.substring(12, 16);

                        list.add(row);
                        row = new Object[4];

                        master_keys.add(mk);

                        master = false;
                    } else {

                        MySubKey sk = new MySubKey();

                        sk.setValid_from(in.next());
                        StringBuilder sb = new StringBuilder();
                        String next = in.next();
                        while (!next.equals("endname")) {
                            sb.append(next + " ");
                            next = in.next();
                        }
                        String name_and_email = sb.toString();
                        System.out.println("name email: " + name_and_email);
                        String[] splitted = name_and_email.split("<");
                        sk.setName(splitted[0]);
                        sk.setEmail(splitted[1].substring(0, splitted[1].length() - 2));
                        sk.setKey_id(in.next());
                        sk.setPublic_key(in.next());
                        sk.setType(in.next());

                        sk.setMaster_key_id(in.next());

                        sub_keys.add(sk);

                        master = true;
                    }

                }
                in.close();
            } catch (FileNotFoundException ex) {
                Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
            }

        }
        /*
        //sort po datumu izgradnje key-a
        Collections.sort(master_keys, new Comparator<MyMasterKey>() {
            @Override
            public int compare(MyMasterKey first, MyMasterKey second) {

                LocalDate first_d = LocalDate.parse(first.getValid_from());
                LocalDate second_d = LocalDate.parse(second.getValid_from());

                if (first_d.isBefore(second_d)) {
                    return -1;
                } else if (first_d.isAfter(second_d)) {
                    return 1;
                } else {
                    return 0;
                }
                //TODO return 1 if rhs should be before lhs 
                //     return -1 if lhs should be before rhs
                //     return 0 otherwise (meaning the order stays the same)
            }
        });

        Collections.sort(sub_keys, new Comparator<MySubKey>() {
            @Override
            public int compare(MySubKey first, MySubKey second) {

                LocalDate first_d = LocalDate.parse(first.getValid_from());
                LocalDate second_d = LocalDate.parse(second.getValid_from());

                if (first_d.isBefore(second_d)) {
                    return -1;
                } else if (first_d.isAfter(second_d)) {
                    return 1;
                } else {
                    return 0;
                }
                //TODO return 1 if rhs should be before lhs 
                //     return -1 if lhs should be before rhs
                //     return 0 otherwise (meaning the order stays the same)
            }
        });
         */
        DefaultTableModel model = new DefaultTableModel();
        JTable table = new JTable(model);

        // Create a couple of columns 
        model.addColumn("Name");
        model.addColumn("E-Mail");
        model.addColumn("Valid From");
        model.addColumn("Key ID");
        // Append a row 

        data = new LinkedList<>();
        for (int i = 0; i < list.size(); i++) {
            Object[] row = list.get(i);
            model.addRow(row);
            data.add(row);
        }

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent event) {
                // do some actions here, for example
                // print first column value from selected row
                int row_index = table.getSelectedRow();
                if (row_index > -1) {
                    JFrame info_frame = get_key_info_frame(frame, screenSize, row_index);
                }
            }
        });
        return table;
    }

    private static JFrame get_key_info_frame(JFrame f, Dimension screenSize, int row_index) {
        JFrame key_info_frame = new JFrame();

        f.setEnabled(false);
        key_info_frame.setResizable(false);

        key_info_frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                f.setEnabled(true);
            }
        });

        key_info_frame.setBounds(screenSize.width / 2 - 200, screenSize.height / 2 - 100, 600, 200);

        //izgled
        JPanel jp = new JPanel(new BorderLayout());

        DefaultTableModel model = new DefaultTableModel();

        JTable table = new JTable(model);

        model.addColumn("Key ID");
        model.addColumn("Type");
        model.addColumn("Valid From");
        model.addColumn("Primary");

        MyMasterKey mk = master_keys.get(row_index);
        MySubKey sk = sub_keys.get(row_index);

        key_info_frame.setTitle(mk.getName() + "<" + mk.getEmail() + ">" + " - " + mk.getKey_id());

        Object[] row = new Object[4];

        String key_id = mk.getKey_id().toUpperCase();
        row[0] = key_id.substring(0, 4) + " " + key_id.substring(4, 8) + " " + key_id.substring(8, 12) + " " + key_id.substring(12, 16);
        row[1] = mk.getType();
        row[2] = mk.getValid_from();
        row[3] = "Yes";
        model.addRow(row);

        key_id = sk.getKey_id().toUpperCase();
        System.out.println("key id " + key_id);
        row[0] = key_id.substring(0, 4) + " " + key_id.substring(4, 8) + " " + key_id.substring(8, 12) + " " + key_id.substring(12, 16);
        row[1] = sk.getType();
        row[2] = sk.getValid_from();
        row[3] = "No";
        model.addRow(row);

        JScrollPane scrollPane = new JScrollPane(table);
        table.setFillsViewportHeight(true);

        jp.add(scrollPane, BorderLayout.CENTER);

        JButton delete_key_button = new JButton("Delete key");
        JButton export_key_button = new JButton("Export Public key");
        JButton export_secret_button = new JButton("Export Secret key");

        JPanel south_panel = new JPanel(new FlowLayout());

        south_panel.add(export_key_button);
        if (mk.isPr_key()) {
            south_panel.add(export_secret_button);
        }
        south_panel.add(delete_key_button);

        delete_key_button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                if (mk.isPr_key()) {
                    JFrame pass_delete = get_pass_delete_private_key_frame(key_info_frame, screenSize, f, row_index);
                } else {
                    JFrame pass_delete = get_pass_delete_public_key_frame(key_info_frame, screenSize, f, row_index);
                }

            }
        });

        export_key_button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFrame export_pub = export_frame(key_info_frame, screenSize, f, row_index);
            }
        });

        export_secret_button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFrame export_private = export_private_frame(key_info_frame, screenSize, f, row_index);
            }
        });
        jp.add(BorderLayout.SOUTH, south_panel);

        key_info_frame.setContentPane(jp);
        key_info_frame.setVisible(true);

        return key_info_frame;
    }

    private static JFrame export_private_frame(JFrame frame, Dimension screenSize, JFrame f, int row_index) {
        JFrame export_key = new JFrame();
        frame.setEnabled(false);
        export_key.setResizable(false);

        exportPrivateKeyFile = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());

        export_key.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                frame.setEnabled(true);
            }
        });

        export_key.setBounds(screenSize.width / 2 - 200, screenSize.height / 2 - 100, 300, 200);
        JPanel jp = new JPanel(new BorderLayout());

        JLabel folder_label = new JLabel("");

        JPanel center_panel = new JPanel();
        center_panel.add(BorderLayout.NORTH, folder_label);

        JLabel pass_label = new JLabel("Enter passphrase: ");
        JPasswordField pass = new JPasswordField();

        JPanel pass_panel = new JPanel(new GridLayout(1, 2));
        pass_panel.add(pass_label);
        pass_panel.add(pass);

        center_panel.add(BorderLayout.CENTER, pass_panel);

        JButton ok_button = new JButton("OK");
        JButton folder_button = new JButton("Choose folder");

        JLabel wrong_label = new JLabel("");
        wrong_label.setForeground(Color.RED);

        ok_button.setEnabled(false);

        pass.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                warn();
            }

            public void warn() {
                //System.out.println("hej");
                if (pass.getText().length() > 0) {
                    ok_button.setEnabled(true);
                } else {
                    ok_button.setEnabled(false);
                }
            }
        });

        folder_button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //exportPrivateKeyFile = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
                exportPrivateKeyFile.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

                int returnValue = exportPrivateKeyFile.showOpenDialog(null);
                // int returnValue = jfc.showSaveDialog(null);

                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = exportPrivateKeyFile.getSelectedFile();
                    folder_label.setText("Folder: " + selectedFile.getAbsolutePath());
                    //System.out.println(selectedFile.getAbsolutePath());
                }

                if (exportPrivateKeyFile != null && exportPrivateKeyFile.getSelectedFile() != null && pass.getText().length() > 0) {
                    ok_button.setEnabled(true);
                    wrong_label.setText("");
                } else {
                    ok_button.setEnabled(false);
                }
            }
        });

        ok_button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                try {
                    if (exportPrivateKeyFile == null || exportPrivateKeyFile.getSelectedFile() == null) {
                        wrong_label.setText("You must choose folder");
                        return;
                    }

                    MyMasterKey mk = master_keys.get(row_index);

                    Security.addProvider(new BouncyCastleProvider());

                    //provera da li je pass ok
                    MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
                    byte[] hashedString = messageDigest.digest(pass.getText().getBytes());

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

                    Signature signature = Signature.getInstance("DSA", "BC");
                    signature.initSign(privateKey);

                    byte[] message = new byte[]{(byte) 'a', (byte) 'b', (byte) 'c'};

                    signature.update(message);

                    byte[] sigBytes = signature.sign();

                    // verify a signature
                    signature.initVerify(publickey);

                    signature.update(message);

                    if (signature.verify(sigBytes)) {
                        /*File f = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + mk.getName() + "_" + mk.getKey_id() + "SECRET.asc");
                        File fileDest = new File(exportPrivateKeyFile.getSelectedFile().getAbsolutePath() + "//" + mk.getName() + "_" + mk.getKey_id() + "_SECRET.asc");
                        fileDest.createNewFile();
                        FileUtils.copyFile(f, fileDest);
                        fileDest.setLastModified(new Date().getTime());
                         */
                        String inputFile = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + mk.getName() + "_" + mk.getKey_id() + "SECRET.asc";

                        String outputFile = exportPrivateKeyFile.getSelectedFile().getAbsolutePath() + "//" + mk.getName() + "_" + mk.getKey_id() + "_SECRET.asc";
                        OutputStream outputStream;

                        System.out.println("treba mi: " + inputFile + ", \n a imam: " + outputFile);
                        try ( InputStream inputStream = new FileInputStream(inputFile)) {

                            outputStream = new FileOutputStream(outputFile);
                            int byteRead;
                            while ((byteRead = inputStream.read()) != -1) {
                                outputStream.write(byteRead);
                            }
                        }
                        outputStream.close();

                    } else {
                        wrong_label.setText("Wrong password");
                        return;
                    }

                    export_key.dispose();
                    frame.dispose();
                    f.setEnabled(true);
                    f.setVisible(true);
                } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | InvalidKeySpecException | SignatureException ex) {
                    Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                } catch (BadPaddingException ex) {
                    wrong_label.setText("Wrong password");
                }

            }
        });

        jp.add(BorderLayout.NORTH, wrong_label);
        jp.add(BorderLayout.CENTER, center_panel);
        JPanel button_panel = new JPanel(new GridLayout(1, 2));

        button_panel.add(folder_button);
        button_panel.add(ok_button);
        jp.add(BorderLayout.SOUTH, button_panel);

        export_key.setContentPane(jp);

        export_key.setVisible(true);
        return export_key;
    }

    private static JFrame export_frame(JFrame frame, Dimension screenSize, JFrame f, int row_index) {
        JFrame export_key = new JFrame();
        frame.setEnabled(false);
        export_key.setResizable(false);

        exportPublicKeyFile = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());

        export_key.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                frame.setEnabled(true);
            }
        });

        export_key.setBounds(screenSize.width / 2 - 200, screenSize.height / 2 - 100, 300, 200);
        JPanel jp = new JPanel(new BorderLayout());

        JLabel folder_label = new JLabel("");

        JPanel center_panel = new JPanel();
        center_panel.add(BorderLayout.CENTER, folder_label);

        JButton ok_button = new JButton("OK");
        JButton folder_button = new JButton("Choose folder");

        JLabel wrong_label = new JLabel("");
        wrong_label.setForeground(Color.RED);

        ok_button.setEnabled(false);

        folder_button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //exportPublicKeyFile = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
                exportPublicKeyFile.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

                int returnValue = exportPublicKeyFile.showOpenDialog(null);
                // int returnValue = jfc.showSaveDialog(null);

                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = exportPublicKeyFile.getSelectedFile();
                    folder_label.setText("Folder: " + selectedFile.getAbsolutePath());
                    //System.out.println(selectedFile.getAbsolutePath());
                }

                if (exportPublicKeyFile != null && exportPublicKeyFile.getSelectedFile() != null) {
                    ok_button.setEnabled(true);
                    wrong_label.setText("");
                } else {
                    ok_button.setEnabled(false);
                }
            }
        });

        ok_button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                try {
                    if (exportPublicKeyFile == null || exportPublicKeyFile.getSelectedFile() == null) {
                        wrong_label.setText("You must choose folder");
                        return;
                    }

                    MyMasterKey mk = master_keys.get(row_index);

                    /*File f = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + mk.getName() + "_" + mk.getKey_id() + "PUBLIC.asc");
                    File fileDest = new File(exportPublicKeyFile.getSelectedFile().getAbsolutePath() + "//" + mk.getName() + "_" + mk.getKey_id() + "_PUBLIC.asc");

                    
                    fileDest.createNewFile();

                    FileUtils.copyFile(f, fileDest);
                    fileDest.setLastModified(new Date().getTime());*/
                    String inputFile = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + mk.getName() + "_" + mk.getKey_id() + "PUBLIC.asc";
                    String outputFile = exportPublicKeyFile.getSelectedFile().getAbsolutePath() + "//" + mk.getName() + "_" + mk.getKey_id() + "_PUBLIC.asc";
                    OutputStream outputStream;
                    try ( InputStream inputStream = new FileInputStream(inputFile)) {
                        outputStream = new FileOutputStream(outputFile);
                        int byteRead;
                        while ((byteRead = inputStream.read()) != -1) {
                            outputStream.write(byteRead);
                        }
                    }
                    outputStream.close();

                } catch (IOException ex) {
                    Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                }

                export_key.dispose();
                frame.dispose();
                f.setEnabled(true);
                f.setVisible(true);
            }
        }
        );

        jp.add(BorderLayout.NORTH, wrong_label);

        jp.add(BorderLayout.CENTER, center_panel);

        JPanel button_panel = new JPanel(new GridLayout(1, 2));

        button_panel.add(folder_button);

        button_panel.add(ok_button);

        jp.add(BorderLayout.SOUTH, button_panel);

        export_key.setContentPane(jp);

        export_key.setVisible(
                true);
        return export_key;
    }

    private static JFrame get_import_key_frame(JFrame frame, Dimension screenSize) {
        JFrame import_frame = new JFrame();
        frame.setEnabled(false);
        import_frame.setResizable(false);

        import_frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                frame.setEnabled(true);
            }
        });

        import_frame.setBounds(screenSize.width / 2 - 200, screenSize.height / 2 - 100, 300, 200);

        //izgled
        JPanel jp = new JPanel(new BorderLayout());

        //Create a file chooser
        JFileChooser jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());

        int returnValue = jfc.showOpenDialog(null);
        // int returnValue = jfc.showSaveDialog(null);

        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = jfc.getSelectedFile();
            System.out.println(selectedFile.getAbsolutePath());
        }

        import_frame.setContentPane(jp);
        import_frame.setVisible(true);
        return import_frame;
    }

    private static JFrame get_import_private_key_frame(JFrame frame, Dimension screenSize) {
        JFrame import_frame = new JFrame();
        frame.setEnabled(false);
        import_frame.setResizable(false);

        jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());

        import_frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                frame.setEnabled(true);
            }
        });

        import_frame.setBounds(screenSize.width / 2 - 200, screenSize.height / 2 - 100, 600, 200);

        //izgled
        JPanel jp = new JPanel(new BorderLayout());

        JLabel label_bad_pass = new JLabel();
        Font font = new Font(null, Font.PLAIN, 12);
        label_bad_pass.setFont(font);
        label_bad_pass.setForeground(Color.RED);

        JLabel label_file = new JLabel();

        JLabel label_pass = new JLabel("Enter passphrase: ");

        JPasswordField pass = new JPasswordField();

        pass.setVisible(true);
        JButton choose_file = new JButton("Choose file");
        JButton import_key = new JButton("Import key");
        import_key.setEnabled(false);

        pass.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                warn();
            }

            public void warn() {
                //System.out.println("hej");
                if (pass.getText().length() > 0) {
                    import_key.setEnabled(true);
                } else {
                    import_key.setEnabled(false);
                }
            }
        });

        import_key.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (jfc == null || jfc.getSelectedFile() == null) {
                    label_bad_pass.setText("File not choosen");
                    return;
                }

                File file = jfc.getSelectedFile();
                if (!FilenameUtils.getExtension(file.getAbsolutePath()).equals("asc")) {
                    label_bad_pass.setText("File exstension must be .asc");
                    return;
                }

                String res = UtilImport.import_secret(file.getAbsolutePath(), pass.getText(), master_keys, sub_keys);
                if (res.equals("public_key")) {
                    label_bad_pass.setText("Public key found where private key expected");
                } else if (res.equals("bad_pass")) {
                    label_bad_pass.setText("Wrong passphrase");
                } else if (res.equals("private_exists")) {
                    label_bad_pass.setText("Private key with this Key ID already exists");
                } else if (res.equals("ok")) {
                    DefaultTableModel model = (DefaultTableModel) central_table.getModel();

                    Object[] row = new Object[4];

                    MyMasterKey mk = master_keys.get(master_keys.size() - 1);
                    MySubKey sk = sub_keys.get(sub_keys.size() - 1);
                    row[0] = mk.getName();
                    row[1] = mk.getEmail();
                    row[2] = mk.getValid_from();
                    row[3] = get_key_id_format(mk.getKey_id());
                    model.addRow(row);
                    data.add(row);

                    System.out.println("mk " + mk.getKey_id() + " , " + mk.getType());
                    UtilExpImp.generate_key_pair(mk, sk, pass.getText());

                    File fileSrc = new File(jfc.getSelectedFile().getAbsolutePath());
                    File fileDest = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + mk.getName() + "_" + mk.getKey_id() + "SECRET.asc");

                    System.out.println("file dest " + fileDest);
                    System.out.println("file src " + fileSrc);
                    try {
                        fileDest.createNewFile();
                        FileUtils.copyFile(fileSrc, fileDest);
                        fileDest.setLastModified(new Date().getTime());
                    } catch (IOException ex) {
                        Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    import_frame.dispose();
                    frame.setEnabled(true);
                    frame.setVisible(true);
                } else {
                    label_bad_pass.setText("Some error occured");
                }
            }
        });

        choose_file.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //Create a file chooser
                //jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());

                int returnValue = jfc.showOpenDialog(null);
                // int returnValue = jfc.showSaveDialog(null);

                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = jfc.getSelectedFile();
                    label_file.setText("File: " + selectedFile.getAbsolutePath());
                    System.out.println(selectedFile.getAbsolutePath());
                }
            }
        });

        JPanel north_panel = new JPanel(new GridLayout(2, 1));
        JPanel center_panel = new JPanel(new GridLayout(1, 1));
        JPanel south_panel = new JPanel(new GridLayout(1, 1));

        north_panel.add(label_bad_pass);
        north_panel.add(label_file);
        center_panel.add(label_pass);
        center_panel.add(pass);
        south_panel.add(choose_file);
        south_panel.add(import_key);

        jp.add(BorderLayout.NORTH, north_panel);

        jp.add(BorderLayout.CENTER, center_panel);

        jp.add(BorderLayout.SOUTH, south_panel);

        import_frame.setContentPane(jp);
        import_frame.setVisible(true);
        return import_frame;
    }

    private static JFrame get_receive_message_frame(JFrame frame, Dimension screenSize) {
        JFrame receive_message_frame = new JFrame();
        frame.setEnabled(false);
        receive_message_frame.setResizable(false);

        receiveMessageFile = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());

        receive_message_frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                frame.setEnabled(true);
            }
        });

        receive_message_frame.setBounds(screenSize.width / 2 - 200, screenSize.height / 2 - 100, 600, 200);

        //izgled
        JPanel jp = new JPanel(new BorderLayout());

        JLabel fileLabel = new JLabel("");
        JLabel errorLabel = new JLabel();
        errorLabel.setForeground(Color.RED);

        JPanel centerPanel = new JPanel(new GridLayout(2, 1));
        JPanel southPanel = new JPanel(new FlowLayout());

        JButton fileButton = new JButton("Choose file");
        JButton decryptButton = new JButton("Decrypt file");
        JButton saveFileButton = new JButton("Save decrypted file");

        saveFileButton.setEnabled(false);

        fileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //receiveMessageFile = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());

                int returnValue = receiveMessageFile.showOpenDialog(null);
                // int returnValue = jfc.showSaveDialog(null);

                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = receiveMessageFile.getSelectedFile();

                }

                if (receiveMessageFile != null && receiveMessageFile.getSelectedFile() != null) {
                    errorLabel.setText("");
                    fileLabel.setText("File: " + receiveMessageFile.getSelectedFile().getAbsolutePath());
                }
            }
        });

        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    saveFileButton.setEnabled(false);
                    if (receiveMessageFile == null || receiveMessageFile.getSelectedFile() == null) {
                        errorLabel.setText("You must choose file");
                        errorLabel.setForeground(Color.RED);
                        return;
                    }

                    File inputFile = receiveMessageFile.getSelectedFile();

                    Security.addProvider(new BouncyCastleProvider());

                    String res = UtilEncDec.decryptFile(inputFile.getAbsolutePath(), sub_keys, master_keys);

                    if (res.equals("sign")) {
                        String inputF = inputFile.getAbsolutePath();
                        FileInputStream in2 = new FileInputStream(inputF);
                        res = UtilEncDec.verifyFile(in2, master_keys, inputF.substring(0, inputF.length() - 4));
                        in2.close();
                        if (res.equals("no_public_key")) {
                            errorLabel.setText("Signature created with unavailable certificate");
                            errorLabel.setForeground(Color.ORANGE);
                            saveFileButton.setEnabled(true);
                        } else if (res.equals("SIGNATURE_no_public_key")) {
                            errorLabel.setText("Signature could not be verified");
                            errorLabel.setForeground(Color.ORANGE);
                            saveFileButton.setEnabled(false);
                        } else if (res.equals("no_type")) {
                            errorLabel.setText("Selected file is not encrypted or signed");
                            errorLabel.setForeground(Color.RED);
                        } else {
                            if (res.startsWith("SIGNATURE")) {
                                errorLabel.setText("Signature from " + res.substring(9) + " is verified.");

                                errorLabel.setForeground(Color.BLUE);
                            } else {
                                errorLabel.setText("File with signature from " + res);
                                saveFileButton.setEnabled(true);
                                errorLabel.setForeground(Color.BLUE);
                            }
                        }
                    } else if (res.equals("no_secret_key")) {
                        errorLabel.setText("Decryption failed. No secret key.");
                        errorLabel.setForeground(Color.RED);
                    } else if (res.equals("no_public_key")) {
                        errorLabel.setText("Signature created with unavailable certificate");
                        errorLabel.setForeground(Color.ORANGE);
                        saveFileButton.setEnabled(true);
                    } else if (res.equals("ok")) {
                        errorLabel.setText("File is decrypted.  You cannot be sure who encrypted this message as it is not signed.");
                        saveFileButton.setEnabled(true);
                        errorLabel.setForeground(Color.BLUE);
                    } else if (res.equals("no_type")) {
                        errorLabel.setText("Selected file is not encrypted or signed file");
                        saveFileButton.setEnabled(false);
                        errorLabel.setForeground(Color.RED);
                    } else {
                        errorLabel.setText("File is decrypted with verified signature from " + res);
                        saveFileButton.setEnabled(true);
                        errorLabel.setForeground(Color.BLUE);
                    }

                } catch (IOException ex) {
                    Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchProviderException ex) {
                    Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                } catch (Exception ex) {
                    Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        });

        saveFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFrame frame_save_file = get_save_file_frame(receive_message_frame, frame, screenSize, receiveMessageFile.getSelectedFile(), 1);
            }
        });

        centerPanel.add(errorLabel);
        centerPanel.add(fileLabel);

        jp.add(BorderLayout.CENTER, centerPanel);

        southPanel.add(fileButton);
        southPanel.add(decryptButton);

        southPanel.add(saveFileButton);

        jp.add(BorderLayout.SOUTH, southPanel);

        receive_message_frame.setContentPane(jp);
        receive_message_frame.setVisible(true);
        return receive_message_frame;
    }

    private static JFrame get_save_file_frame(JFrame receive_message_frame, JFrame frame, Dimension screenSize, File fileName, int type) {
        JFrame save_file_frame = new JFrame();
        receive_message_frame.setEnabled(false);
        save_file_frame.setResizable(false);

        saveMessageFile = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());

        save_file_frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                receive_message_frame.setEnabled(true);
            }
        });

        save_file_frame.setBounds(screenSize.width / 2 - 200, screenSize.height / 2 - 100, 600, 200);

        //izgled
        JPanel jp = new JPanel(new BorderLayout());

        JLabel folderLabel = new JLabel();
        JLabel errorLabel = new JLabel();
        errorLabel.setForeground(Color.RED);

        JButton folderButton = new JButton("Choose folder");
        JButton okButton = new JButton("Save");

        JPanel centerPanel = new JPanel(new GridLayout(2, 1));

        centerPanel.add(errorLabel);
        centerPanel.add(folderLabel);

        jp.add(BorderLayout.CENTER, centerPanel);

        folderButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                // saveMessageFile = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
                saveMessageFile.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

                int returnValue = saveMessageFile.showOpenDialog(null);
                // int returnValue = jfc.showSaveDialog(null);

                if (returnValue == JFileChooser.APPROVE_OPTION) {

                    File selectedFile = saveMessageFile.getSelectedFile();

                }

                if (saveMessageFile != null && saveMessageFile.getSelectedFile() != null) {
                    errorLabel.setText("");
                    folderLabel.setText("Folder: " + saveMessageFile.getSelectedFile().getAbsolutePath());
                }
            }
        });

        okButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {

                    if (saveMessageFile == null || saveMessageFile.getSelectedFile() == null) {
                        errorLabel.setText("You must choose folder");
                        return;
                    }
                    String name = fileName.getName();
                    if (type == 1) {
                        name = name.substring(0, name.length() - 4);
                    } else {
                        name = name.concat(".asc");
                    }
                    File fileDest = new File(saveMessageFile.getSelectedFile().getAbsolutePath() + "//" + name);
                    File fileSrc = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + name);

                    System.out.println("file dest " + fileDest);
                    System.out.println("file src " + fileSrc);
                    fileDest.createNewFile();
                    FileUtils.copyFile(fileSrc, fileDest);
                    fileDest.setLastModified(new Date().getTime());

                    save_file_frame.dispose();
                    receive_message_frame.dispose();
                    frame.setEnabled(true);
                    frame.setVisible(true);

                } catch (IOException ex) {
                    Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });

        JPanel southPanel = new JPanel(new FlowLayout());

        southPanel.add(folderButton);
        southPanel.add(okButton);

        jp.add(BorderLayout.SOUTH, southPanel);
        save_file_frame.setContentPane(jp);
        save_file_frame.setVisible(true);

        return save_file_frame;
    }

    private static JFrame get_send_message_frame(JFrame frame, Dimension screenSize) {
        JFrame send_message_frame = new JFrame();
        frame.setEnabled(false);
        send_message_frame.setResizable(false);
        sendMessageFile = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());

        send_message_frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                frame.setEnabled(true);
            }
        });

        send_message_frame.setBounds(screenSize.width / 2 - 250, screenSize.height / 2 - 100, 700, 180 + 10 * sub_keys.size());

        //izgled
        JPanel jp = new JPanel(new BorderLayout());

        JButton fileButton = new JButton("Choose file");
        JButton sendMessage = new JButton("Create message");
        JButton saveFile = new JButton("Save message");
        saveFile.setEnabled(false);

        JLabel fileLabel = new JLabel();
        JLabel errorLabel = new JLabel();
        errorLabel.setForeground(Color.RED);

        JCheckBox sign_as_box = new JCheckBox("Sign as: ", true);
        String[] privateKeys = new String[num_private_keys(master_keys)];
        Object[][] publicKeys = new Object[master_keys.size()][2];

        int j = 0;
        for (int i = 0; i < master_keys.size(); i++) {
            MyMasterKey mk = master_keys.get(i);
            if (mk.isPr_key()) {
                privateKeys[j] = mk.getName() + "<" + mk.getEmail() + ">" + "-" + get_key_id_format(mk.getKey_id());
                j++;
            }
            publicKeys[i][0] = mk.getName() + "<" + mk.getEmail() + ">" + "-" + get_key_id_format(mk.getKey_id());

            publicKeys[i][1] = false;

        }

        JComboBox privateKeysCombo = new JComboBox(privateKeys);
        privateKeysCombo.setEnabled(true);

        JCheckBox encrypt_for = new JCheckBox("Encrypt for: ", true);

        /* Object[] column_names = {"Key", ""};
        JTable publicKeysTable = new JTable(publicKeys, column_names);

        JScrollPane tableScroll = new JScrollPane(publicKeysTable);*/
        ButtonGroup groupEncAlg = new ButtonGroup();

        JRadioButton castRadio = new JRadioButton("CAST5");
        castRadio.setSelected(true);

        JRadioButton desRadio = new JRadioButton("3DES");
        desRadio.setSelected(false);

        groupEncAlg.add(castRadio);
        groupEncAlg.add(desRadio);

        JLabel algLabel = new JLabel("Encryption algorithm: ");

        JPanel algPanel = new JPanel(new FlowLayout());

        JPanel north_panel = new JPanel(new GridLayout(2, 1));
        JPanel center_panel = new JPanel(new BorderLayout());

        JPanel south_panel = new JPanel(new GridLayout(1, 3));

        north_panel.add(fileLabel);
        north_panel.add(errorLabel);

        JPanel n_panel = new JPanel(new GridLayout(1, 2));

        n_panel.add(sign_as_box);
        n_panel.add(privateKeysCombo);

        center_panel.add(BorderLayout.NORTH, n_panel);

        JPanel c_panel = new JPanel(new GridLayout(1, 2));

        c_panel.add(encrypt_for);

        JPanel tablePanel = new JPanel(new GridLayout(sub_keys.size(), 1));
        JCheckBox[] boxes = new JCheckBox[sub_keys.size()];

        for (int i = 0; i < sub_keys.size(); i++) {
            MySubKey sk = sub_keys.get(i);
            System.out.println("sk " + sk.getKey_id());
            boxes[i] = new JCheckBox(sk.getName() + "<" + sk.getEmail() + ">" + "-" + get_key_id_format(sk.getKey_id()));
            if (i > 0) {
                boxes[i].setSelected(false);
            } else {
                boxes[i].setSelected(true);
            }
            tablePanel.add(boxes[i]);
        }

        c_panel.add(tablePanel);

        center_panel.add(BorderLayout.CENTER, c_panel);

        JPanel s_panel = new JPanel(new GridLayout(1, 2));

        algPanel.add(castRadio);
        algPanel.add(desRadio);

        s_panel.add(algLabel);
        s_panel.add(algPanel);

        center_panel.add(BorderLayout.SOUTH, s_panel);

        privateKeysCombo.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if (e.getStateChange() == ItemEvent.SELECTED) {
                    if (master_keys != null && master_keys.size() > 0) {
                        MyMasterKey mk = master_keys.get(0);
                        int j = 1;

                        //System.out.println("mk " + mk.getName() + "<" + mk.getEmail() + ">" + "-" + get_key_id_format(mk.getKey_id()));
                        //System.out.println("getItem " + e.getItem());
                        while (!e.getItem().equals(mk.getName() + "<" + mk.getEmail() + ">" + "-" + get_key_id_format(mk.getKey_id())) && j < num_private_keys(master_keys)) {
                            mk = master_keys.get(j);
                            j++;
                        }

                        //System.out.println("mk key id " + mk.getKey_id());
                        //System.out.println("sub key master id " + sub_keys.get(j - 1).getMaster_key_id());
                        if (mk.getKey_id().equals(sub_keys.get(j - 1).getMaster_key_id())) {
                            boxes[j - 1].setSelected(true);
                        }
                    }
                }
            }
        });

        sign_as_box.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (sign_as_box.isSelected()) {
                    privateKeysCombo.setEnabled(true);
                    sendMessage.setEnabled(true);
                } else {
                    privateKeysCombo.setEnabled(false);
                    if (!encrypt_for.isSelected()) {
                        sendMessage.setEnabled(false);
                    }
                }
            }
        });

        encrypt_for.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (encrypt_for.isSelected()) {

                    castRadio.setEnabled(true);
                    desRadio.setEnabled(true);
                    for (int i = 0; i < boxes.length; i++) {
                        boxes[i].setEnabled(true);
                    }

                    sendMessage.setEnabled(true);
                } else {
                    castRadio.setEnabled(false);
                    desRadio.setEnabled(false);
                    for (int i = 0; i < boxes.length; i++) {
                        boxes[i].setEnabled(false);
                    }

                    if (!sign_as_box.isSelected()) {
                        sendMessage.setEnabled(false);
                    }
                }
            }
        });

        fileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //sendMessageFile = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
                //sendMessageFile.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

                int returnValue = sendMessageFile.showOpenDialog(null);
                // int returnValue = jfc.showSaveDialog(null);

                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = sendMessageFile.getSelectedFile();
                    fileLabel.setText("File to send: " + selectedFile.getAbsolutePath());
                    System.out.println(selectedFile.getAbsolutePath());
                }

                if (sendMessageFile != null && sendMessageFile.getSelectedFile() != null) {
                    errorLabel.setText("");
                } else {
                    errorLabel.setText("You must select a file");
                }
            }
        });

        fileName = null;
        sendMessage.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                errorLabel.setForeground(Color.RED);
                boolean encryption = false;
                boolean sign = false;
                MyMasterKey mk = null;
                List<MySubKey> sub_key = new LinkedList<>();
                int encAlg;

                if (desRadio.isSelected()) {
                    encAlg = PGPEncryptedData.TRIPLE_DES;
                } else {
                    encAlg = PGPEncryptedData.CAST5;
                }

                if (sendMessageFile == null || sendMessageFile.getSelectedFile() == null) {
                    errorLabel.setText("You must select a file");
                    return;
                }

                fileName = sendMessageFile.getSelectedFile();

                if (sign_as_box.isSelected()) {
                    sign = true;
                    int index = privateKeysCombo.getSelectedIndex();
                    int i = -1;
                    int j = -1;
                    while (i != index) {
                        j++;
                        if (master_keys.get(j).isPr_key()) {
                            i++;
                        }
                    }

                    mk = master_keys.get(j);
                }

                if (encrypt_for.isSelected()) {
                    encryption = true;
                    for (int i = 0; i < boxes.length; i++) {
                        if (boxes[i].isSelected()) {
                            sub_key.add(sub_keys.get(i));
                        }
                    }

                    if (sub_key.isEmpty()) {
                        errorLabel.setText("You must choose at least one person to encrypt message for");
                        return;
                    }
                }

                if (sign) {
                    JFrame frame_pass_mess = get_password_frame_message(encryption, sign, mk, sub_key, encAlg, send_message_frame, frame, screenSize, saveFile, errorLabel);

                } else {
                    String res = send_message(encryption, sign, mk, sub_key, null, encAlg);
                    if (res.equals("ok")) {
                        errorLabel.setText("File is encrypted!");
                        errorLabel.setForeground(Color.BLUE);
                        saveFile.setEnabled(true);
                        //send_message_frame.dispose();

                        //frame.setEnabled(true);
                        //frame.setVisible(true);
                    } else if (res.equals("error")) {
                        errorLabel.setText("Some error occured while encrypting file");
                    }
                }

            }
        });

        saveFile.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                JFrame save_file_frame = get_save_file_frame(send_message_frame, frame, screenSize, fileName, 0);
            }
        });

        south_panel.add(fileButton);
        south_panel.add(sendMessage);
        south_panel.add(saveFile);

        jp.add(BorderLayout.NORTH, north_panel);
        jp.add(BorderLayout.SOUTH, south_panel);
        jp.add(BorderLayout.CENTER, center_panel);

        send_message_frame.setContentPane(jp);
        send_message_frame.setVisible(true);
        return send_message_frame;
    }

    /*
    private static JFrame get_save_file_frame(JFrame frame, JFrame f, Dimension screenSize, String fileName) {
        JFrame save_file_frame = new JFrame();

        saveFileFile = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
        frame.setEnabled(false);
        save_file_frame.setResizable(false);

        save_file_frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                frame.setEnabled(true);
            }
        });

        save_file_frame.setBounds(screenSize.width / 2 - 200, screenSize.height / 2 - 100, 600, 150);

        //izgled
        JPanel jp = new JPanel(new BorderLayout());

        JLabel errorLabel = new JLabel("");
        errorLabel.setForeground(Color.RED);

        JLabel fileLabel = new JLabel("");

        JButton chooseFile = new JButton("Choose file");
        JButton okButton = new JButton("Save");
        okButton.setEnabled(false);

        okButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });

        chooseFile.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                saveFileFile.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

                int returnValue = saveFileFile.showOpenDialog(null);
                // int returnValue = jfc.showSaveDialog(null);

                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = saveFileFile.getSelectedFile();
                    fileLabel.setText("Folder: " + selectedFile.getAbsolutePath());
                    errorLabel.setText("");
                }

                if (saveFileFile == null || saveFileFile.getSelectedFile() == null) {
                    errorLabel.setText("You must choose file");
                }

            }
        });

        JPanel centerPanel = new JPanel(new GridLayout(2, 1));

        centerPanel.add(errorLabel);
        centerPanel.add(fileLabel);

        jp.add(BorderLayout.CENTER, centerPanel);

        JPanel southPanel = new JPanel(new FlowLayout());

        southPanel.add(okButton);
        southPanel.add(chooseFile);

        jp.add(BorderLayout.SOUTH, southPanel);

        save_file_frame.setContentPane(jp);
        save_file_frame.setVisible(true);

        return save_file_frame;
    }
     */
    private static JFrame get_password_frame_message(boolean encryption, boolean sign, MyMasterKey mk, List<MySubKey> sub_key, int encAlg, JFrame send_message_frame, JFrame f, Dimension screenSize, JButton button, JLabel label) {
        JFrame pass_frame = new JFrame();

        send_message_frame.setEnabled(false);
        pass_frame.setResizable(false);

        pass_frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                send_message_frame.setEnabled(true);
            }
        });

        pass_frame.setBounds(screenSize.width / 2 - 200, screenSize.height / 2 - 100, 600, 150);

        //izgled
        JPanel jp = new JPanel(new BorderLayout());

        JLabel wrongPass = new JLabel("");
        wrongPass.setForeground(Color.RED);

        JLabel passLabel = new JLabel("<html>Enter passphrase for :<br>" + mk.getName() + "     <" + mk.getEmail() + "> - " + mk.getKey_id().toUpperCase() + " </html>");

        JPasswordField passField = new JPasswordField();

        JButton okButton = new JButton("OK");
        okButton.setEnabled(false);

        passField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                warn();
            }

            public void warn() {
                //System.out.println("hej");
                if (passField.getText().length() > 0) {
                    okButton.setEnabled(true);
                } else {
                    okButton.setEnabled(false);
                }
            }
        });

        okButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String res = send_message(encryption, sign, mk, sub_key, passField.getText(), encAlg);
                if (res.equals("ok")) {
                    label.setText("File is created!");
                    label.setForeground(Color.BLUE);
                    button.setEnabled(true);
                    pass_frame.dispose();
                    send_message_frame.setEnabled(true);
                    send_message_frame.setVisible(true);
                    //send_message_frame.dispose();
                    //f.setEnabled(true);
                    //f.setVisible(true);
                } else if (res.equals("wrong_pass")) {
                    wrongPass.setText("Wrong passphrase");
                } else if (res.equals("error")) {

                    wrongPass.setText("Some error occured while encrypting file");
                }
            }
        });

        JPanel centerPanel = new JPanel(new GridLayout(1, 2));
        centerPanel.add(passLabel);
        centerPanel.add(passField);

        jp.add(BorderLayout.NORTH, wrongPass);
        jp.add(BorderLayout.CENTER, centerPanel);
        jp.add(BorderLayout.SOUTH, okButton);

        pass_frame.setContentPane(jp);
        pass_frame.setVisible(true);

        return pass_frame;

    }

    private static String send_message(boolean encryption, boolean sign, MyMasterKey mk, List<MySubKey> sub_key, String pass, int encAlg) {
        Security.addProvider(new BouncyCastleProvider());

        String file_name = sendMessageFile.getSelectedFile().getAbsolutePath();
        String privateKey = null;
        List<String> publicKeys = new LinkedList<>();

        if (sign) {
            try {
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

                PrivateKey privateK = kf.generatePrivate(new PKCS8EncodedKeySpec(decrypted_private_key));

                X509EncodedKeySpec keySpecX509
                        = new X509EncodedKeySpec(Hex.decode(mk.getPublic_key()));

                //System.out.println("keySpec: " + mk.getPublic_key());
                PublicKey publicK = kf.generatePublic(keySpecX509);

                Signature signature = Signature.getInstance("DSA", "BC");
                signature.initSign(privateK);

                byte[] message = new byte[]{(byte) 'a', (byte) 'b', (byte) 'c'};

                signature.update(message);

                byte[] sigBytes = signature.sign();

                // verify a signature
                signature.initVerify(publicK);

                signature.update(message);

                if (!signature.verify(sigBytes)) {
                    return "wrong_pass";
                }

                privateKey = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + mk.getName() + "_" + mk.getKey_id() + "SECRET.asc";
            } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | InvalidKeySpecException | SignatureException ex) {
                Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                return "error";
            } catch (BadPaddingException ex) {
                return "wrong_pass";
            }

        }

        if (encryption) {
            for (int i = 0; i < sub_key.size(); i++) {
                String s = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + sub_key.get(i).getName() + "_" + sub_key.get(i).getMaster_key_id() + "PUBLIC.asc";
                publicKeys.add(s);
            }
        }

        File f = new File(file_name);
        String dir = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + f.getName();

        if (encryption && sign) {
            try {
                UtilEncDec.signEncrypt(dir + ".asc", file_name, publicKeys, privateKey, pass, encAlg);
            } catch (Exception ex) {
                Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                return "error";
            }
        } else if (encryption) {
            try {
                UtilEncDec.encryptFile(dir + ".asc", file_name, publicKeys, encAlg, true, true);
            } catch (IOException | NoSuchProviderException | PGPException ex) {
                Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                return "error";
            }
        } else if (sign) {
            try {
                UtilEncDec.signFile(file_name, privateKey, pass.toCharArray(), true);
            } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | PGPException | SignatureException ex) {
                Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                return "error";
            }
        }

        return "ok";
    }

    private static JFrame get_import_public_key_frame(JFrame frame, Dimension screenSize) {
        JFrame import_frame = new JFrame();
        frame.setEnabled(false);
        import_frame.setResizable(false);

        jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp");

        import_frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                frame.setEnabled(true);
            }
        });

        import_frame.setBounds(screenSize.width / 2 - 200, screenSize.height / 2 - 100, 600, 200);

        //izgled
        JPanel jp = new JPanel(new BorderLayout());

        JLabel label_bad = new JLabel();
        Font font = new Font(null, Font.PLAIN, 12);
        label_bad.setFont(font);
        label_bad.setForeground(Color.RED);

        JLabel label_file = new JLabel();

        JButton choose_file = new JButton("Choose file");
        JButton import_key = new JButton("Import key");

        import_key.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (jfc == null || jfc.getSelectedFile() == null) {
                    label_bad.setText("File not choosen");
                    return;
                }

                File file = jfc.getSelectedFile();
                if (!FilenameUtils.getExtension(file.getAbsolutePath()).equals("asc")) {
                    label_bad.setText("File exstension must be .asc");
                    return;
                }

                String res = UtilImport.import_public(file.getAbsolutePath(), master_keys, sub_keys);
                if (res.equals("secret_key")) {
                    label_bad.setText("Private key found where public key expected");

                } else if (res.equals("private_exists")) {
                    label_bad.setText("Private key with this Key ID already exists");
                } else if (res.equals("public_exists")) {
                    label_bad.setText("Public key with this Key ID already exists");
                } else if (res.equals("ok")) {
                    DefaultTableModel model = (DefaultTableModel) central_table.getModel();

                    Object[] row = new Object[4];

                    MyMasterKey mk = master_keys.get(master_keys.size() - 1);
                    row[0] = mk.getName();
                    row[1] = mk.getEmail();
                    row[2] = mk.getValid_from();
                    row[3] = get_key_id_format(mk.getKey_id());
                    model.addRow(row);
                    data.add(row);

                    File fileDest = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + mk.getName() + "_" + mk.getKey_id() + "PUBLIC.asc");
                    File fileSrc = new File(file.getAbsolutePath());
                    try {
                        fileDest.createNewFile();
                        FileUtils.copyFile(fileSrc, fileDest);
                    } catch (IOException ex) {
                        Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                    }

                    fileDest.setLastModified(new Date().getTime());

                    import_frame.dispose();
                    frame.setEnabled(true);
                    frame.setVisible(true);
                } else {
                    label_bad.setText("Some error occured");
                }
            }
        });

        choose_file.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //Create a file chooser
                //jfc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp");

                int returnValue = jfc.showOpenDialog(null);
                // int returnValue = jfc.showSaveDialog(null);

                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = jfc.getSelectedFile();
                    label_file.setText("File: " + selectedFile.getAbsolutePath());
                    System.out.println(selectedFile.getAbsolutePath());
                }
            }
        });

        JPanel center_panel = new JPanel(new GridLayout(2, 1));
        JPanel south_panel = new JPanel(new GridLayout(1, 1));

        center_panel.add(label_bad);
        center_panel.add(label_file);
        south_panel.add(choose_file);
        south_panel.add(import_key);

        jp.add(BorderLayout.CENTER, center_panel);

        jp.add(BorderLayout.SOUTH, south_panel);

        import_frame.setContentPane(jp);
        import_frame.setVisible(true);
        return import_frame;
    }

    private static JFrame get_pass_delete_public_key_frame(JFrame frame, Dimension screenSize, JFrame f, int row_index) {

        JFrame delete_key = new JFrame();
        frame.setEnabled(false);
        delete_key.setResizable(false);

        delete_key.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                frame.setEnabled(true);
            }
        });

        delete_key.setBounds(screenSize.width / 2 - 200, screenSize.height / 2 - 100, 300, 200);

        //izgled
        JPanel jp = new JPanel(new BorderLayout());

        JLabel label = new JLabel("Are you sure you want to delete public key?");

        jp.add(BorderLayout.CENTER, label);

        JButton ok_button = new JButton("Ok");
        JButton cancel_button = new JButton("Cancel");

        JPanel buttonPanel = new JPanel(new FlowLayout());

        ok_button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {

                    MyMasterKey mk = master_keys.get(row_index);

                    DefaultTableModel model = (DefaultTableModel) central_table.getModel();
                    model.removeRow(row_index);

                    mk = master_keys.remove(row_index);
                    sub_keys.remove(row_index);

                    //sta se desava sa ljudima koji imaju ovaj kljuc kod sebe u prstenu javnih kljuceva
                    String key_id = mk.getKey_id();
                    String user_id = mk.getName() + "<" + mk.getEmail() + ">";
                    String valid_from = mk.getValid_from();

                    File public_keyring = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp/public_keyring.txt");

                    Scanner in = new Scanner(new InputStreamReader(new FileInputStream(public_keyring.getAbsolutePath()), StandardCharsets.UTF_8));
                    StringBuilder sb = new StringBuilder();

                    String line;
                    while (in.hasNext()) {
                        line = in.nextLine();
                        String test = line.substring(line.indexOf("endname"), line.length());
                        String[] data = test.split(" ");

                        if (!data[1].equals(key_id)) {
                            //System.out.println("Isto je sve: " + data[0] + " " + data[1] + " " + data[2]);
                            sb.append(line).append("\n");
                            line = in.nextLine();
                            sb.append(line).append("\n");
                        } else {
                            //System.out.println("Nije isto sve: " + data[0] + " " + data[1] + " " + data[2]);
                            line = in.nextLine();
                        }
                    }

                    in.close();

                    System.out.println(sb.toString());

                    public_keyring.delete();

                    public_keyring.createNewFile();
                    Files.write(Paths.get(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//public_keyring.txt"), sb.toString().getBytes(), StandardOpenOption.WRITE);

                    //System.out.println("OVDE SAM DEBILI");
                    Files.deleteIfExists(Paths.get(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + mk.getName() + "_" + mk.getKey_id() + "PUBLIC.asc"));

                    //System.out.println("OVDE SAM DEBILI ISTO");
                    delete_key.dispose();
                    frame.dispose();
                    f.setEnabled(true);

                    f.setVisible(true);

                } catch (FileNotFoundException ex) {
                    Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });

        cancel_button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                delete_key.dispose();
                f.setVisible(true);
                frame.setEnabled(true);
                frame.setVisible(true);
            }
        });

        buttonPanel.add(ok_button);
        buttonPanel.add(cancel_button);

        jp.add(BorderLayout.SOUTH, buttonPanel);

        delete_key.setContentPane(jp);

        delete_key.setVisible(true);
        return delete_key;
    }

    private static JFrame get_pass_delete_private_key_frame(JFrame frame, Dimension screenSize, JFrame f, int row_index) {

        JFrame delete_key = new JFrame();
        frame.setEnabled(false);
        delete_key.setResizable(false);

        delete_key.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                frame.setEnabled(true);
            }
        });

        delete_key.setBounds(screenSize.width / 2 - 200, screenSize.height / 2 - 100, 300, 200);

        //izgled
        JPanel jp = new JPanel(new BorderLayout());

        JLabel pass_label = new JLabel("Enter passphrase: ");
        JPasswordField pass = new JPasswordField();

        JPanel center_panel = new JPanel(new GridLayout(1, 2));
        center_panel.add(pass_label);
        center_panel.add(pass);

        JButton ok_button = new JButton("OK");

        ok_button.setEnabled(false);

        JLabel wronglabel = new JLabel();
        wronglabel.setForeground(Color.RED);

        pass.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                warn();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                warn();
            }

            public void warn() {
                //System.out.println("hej");
                if (pass.getText().length() > 0) {
                    ok_button.setEnabled(true);
                } else {
                    ok_button.setEnabled(false);
                }
            }
        });

        ok_button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    Security.addProvider(new BouncyCastleProvider());
                    MyMasterKey mk = master_keys.get(row_index);

                    //provera da li je pass ok
                    MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
                    byte[] hashedString = messageDigest.digest(pass.getText().getBytes());

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

                    //String decryptedValue = new String(decrypted_private_key);
                    //String decoded = new String(base64.decode(decryptedValue));
                    // System.out.println("decoded: " + decrypted_private_key.toString());
                    //System.out.println("public " + mk.getPublic_key());
                    //System.out.println("decoded pu: " + base64.decode(mk.getPublic_key()).toString());
                    //SecretKey original_dsa_private = new SecretKeySpec(decrypted_private_key, "DSA");
                    KeyFactory kf = KeyFactory.getInstance("DSA");

                    PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(decrypted_private_key));

                    X509EncodedKeySpec keySpecX509
                            = new X509EncodedKeySpec(Hex.decode(mk.getPublic_key()));

                    PublicKey publickey = kf.generatePublic(keySpecX509);
                    /*
                    java.util.Base64.Encoder encoder = java.util.Base64.getEncoder();

                    byte[] bb;

                    byte[] k = publickey.getEncoded();
                    int size = 1 + publickey.getEncoded().length;
                    bb = new byte[size];
                    bb[0] = 0x06;
                    for (int i = 1; i < size; i++) {
                        bb[i] = k[i - 1];
                    }
                    String sub = encoder.encodeToString(bb);

                    byte[] b = new String(publickey.getEncoded()).getBytes();
                    long res = to_crc(bb, bb.length);
                    System.out.println("res: " + res);
                    System.out.println("res hex: " + Long.toHexString(res));
                    b = UtilHex.toByteArray(Long.toHexString(res));
                    System.out.println("base64: " + java.util.Base64.getEncoder().encode(b));

                    byte[] decodedHex = org.apache.commons.codec.binary.Hex.decodeHex(Long.toHexString(res));
                    String s = java.util.Base64.getEncoder().encodeToString(decodedHex);
                    System.out.println("encoder: " + s);

                    System.out.println("sub: " + sub);;
                    String outFile = FileSystemView.getFileSystemView().getHomeDirectory() + "//zp/proba_public";
                    Writer out = new FileWriter(outFile + ".asc");
                    out.write("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n");
                    for (int i = 0; i < sub.length(); i = i + 64) {
                        if (i + 64 <= sub.length()) {
                            out.write(sub.substring(i, i + 64) + "\n");
                        } else {
                            out.write(sub.substring(i, sub.length()) + "\n");
                        }

                    }

                    out.write("=" + s + "\n");
                    out.write("-----END PGP PUBLIC KEY BLOCK-----\n");
                    out.close();*/
 /*
                    byte[] key = Hex.decode(mk.getPublic_key());

                    byte[] deco = base64.decode(mk.getPublic_key());
                     
                    
                    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA", "BC");

                    KeyPair keyPair = keyPairGenerator.generateKeyPair();

                    DSAPrivateKey privateKey_dsa = (DSAPrivateKey) keyPair.getPrivate();
                    DSAPublicKey publicKey_dsa = (DSAPublicKey) keyPair.getPublic();
                     */
                    //System.out.println("good format " + keyPair.getPublic().getEncoded());
                    //System.out.println("bad format " + UtilHex.toByteArray(mk.getPublic_key()));
                    // SecretKeySpec original_dsa_public = new SecretKeySpec(publicKey_dsa.getEncoded(), "DSA");

                    Signature signature = Signature.getInstance("DSA", "BC");
                    signature.initSign(privateKey);

                    byte[] message = new byte[]{(byte) 'a', (byte) 'b', (byte) 'c'};

                    signature.update(message);

                    byte[] sigBytes = signature.sign();

                    // verify a signature
                    signature.initVerify(publickey);

                    signature.update(message);

                    if (signature.verify(sigBytes)) {
                        System.out.println("signature verification succeeded.");
                    } else {
                        wronglabel.setText("Wrong password");
                        System.out.println("signature verification failed.");
                        return;
                    }
                    /*
                    String test_message = "everything_ok";

                    c = Cipher.getInstance("DSA", "BC");

                    SecretKey original_dsa_public = new SecretKeySpec(mk.getPublic_key().getBytes(), "DSA");
                    c.init(Cipher.ENCRYPT_MODE, original_dsa_public);
                    byte[] encrypted_message = c.doFinal(test_message.getBytes());

                    SecretKey original_dsa_private = new SecretKeySpec(decrypted_private_key, "DSA");
                    c.init(Cipher.DECRYPT_MODE, original_dsa_private);
                    byte[] decrypted_message = c.doFinal(encrypted_message);

                    if (test_message.equals(base64.encodeToString(decrypted_message))) {
                        System.out.println("Passphrase is legit!");
                    } else {
                        System.out.println("Passphrase is not good!");
                    }*/

                    DefaultTableModel model = (DefaultTableModel) central_table.getModel();
                    model.removeRow(row_index);

                    mk = master_keys.remove(row_index);
                    sub_keys.remove(row_index);

                    //sta se desava sa ljudima koji imaju ovaj kljuc kod sebe u prstenu javnih kljuceva
                    String key_id = mk.getKey_id();
                    String user_id = mk.getName() + "<" + mk.getEmail() + ">";
                    String valid_from = mk.getValid_from();

                    File private_keyring = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp/private_keyring.txt");

                    Scanner in = new Scanner(new InputStreamReader(new FileInputStream(private_keyring.getAbsolutePath()), StandardCharsets.UTF_8));
                    StringBuilder sb = new StringBuilder();

                    String line;
                    while (in.hasNext()) {
                        line = in.nextLine();
                        String test = line.substring(line.indexOf("endname"), line.length());
                        String[] data = test.split(" ");

                        if (!data[1].equals(key_id)) {
                            System.out.println("Isto je sve: " + data[0] + " " + data[1] + " " + data[2]);
                            sb.append(line).append("\n");
                            line = in.nextLine();
                            sb.append(line).append("\n");
                        } else {
                            System.out.println("Nije isto sve: " + data[0] + " " + data[1] + " " + data[2]);
                            line = in.nextLine();
                        }
                    }

                    in.close();

                    System.out.println(sb.toString());

                    private_keyring.delete();

                    private_keyring.createNewFile();
                    Files.write(Paths.get(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//private_keyring.txt"), sb.toString().getBytes(), StandardOpenOption.WRITE);

                    Files.deleteIfExists(Paths.get(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + mk.getName() + "_" + mk.getKey_id() + "PUBLIC.asc"));
                    Files.deleteIfExists(Paths.get(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + mk.getName() + "_" + mk.getKey_id() + "SECRET.asc"));
                    /*
                    File fPub = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + mk.getName() + "_" + mk.getKey_id() + "PUBLIC.asc");
                    File fSec = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys//" + mk.getName() + "_" + mk.getKey_id() + "SECRET.asc");

                    System.out.println("trazio sam public file: " + fPub.getAbsolutePath());
                    System.out.println("trazio sam private file: " + fSec.getAbsolutePath());
                    if (fPub.exists()) {
                        System.out.println("Postoji file");
                    } else {
                        System.out.println("VISE NE POSTOJI NEE");
                    }
                    fPub.delete();
                    fSec.delete();

                    if (!fPub.exists()) {
                        System.out.println("Vise ne postoji");
                    }*/
                    System.out.println("Funkija delete je zavrsena");
                    delete_key.dispose();
                    frame.dispose();
                    f.setEnabled(true);

                    f.setVisible(true);

                } catch (FileNotFoundException ex) {
                    Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException | NoSuchAlgorithmException ex) {
                    Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                } catch (BadPaddingException ex) {
                    wronglabel.setText("Wrong password");
                    System.out.println("Bad password");
                } catch (InvalidKeySpecException | InvalidKeyException | IllegalBlockSizeException | NoSuchProviderException | NoSuchPaddingException | SignatureException ex) {
                    Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });

        jp.add(BorderLayout.NORTH, wronglabel);
        jp.add(BorderLayout.CENTER, center_panel);
        jp.add(BorderLayout.SOUTH, ok_button);

        delete_key.setContentPane(jp);

        delete_key.setVisible(true);
        return delete_key;
    }

    public static void exportPublicKey(
            OutputStream publicOut,
            KeyPair dsaKp,
            KeyPair elgKp,
            String identity,
            char[] passPhrase,
            boolean armor, Date d)
            throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException, NoSuchAlgorithmException {
        if (armor) {
            // secretOut = new ArmoredOutputStream(secretOut);
        }

        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, d);

        System.out.println("dsa " + Long.toHexString(dsaKeyPair.getPublicKey().getKeyID()));
        PGPKeyPair elgKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, d);
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
                identity, sha1Calc, null, null, new JcaPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase));

        keyRingGen.addSubKey(elgKeyPair);

        //keyRingGen.generateSecretKeyRing().encode(secretOut);
        //System.out.println("Public Key: algorithm-> " + dsaKeyPair.getPublicKey().getAlgorithm() + " bit strength-> " + dsaKeyPair.getPublicKey().getBitStrength() + " creation time-> " + dsaKeyPair.getPublicKey().getCreationTime() + " fingerprint-> " + UtilHex.toHex(dsaKeyPair.getPublicKey().getFingerprint()) + " key id-> " + dsaKeyPair.getPublicKey().getKeyID() + " key len-> " + UtilHex.toHex(dsaKeyPair.getPublicKey().getEncoded()).length() + " ");
        //secretOut.close();
        if (armor) {
            publicOut = new ArmoredOutputStream(publicOut);
        }

        keyRingGen.generatePublicKeyRing().encode(publicOut);
        /*Iterator<PGPPublicKey> it = keyRingGen.generatePublicKeyRing().iterator();
        while (it.hasNext()) {
            PGPPublicKey pk = it.next();
            System.out.println("key public: " + UtilHex.toHex(pk.getFingerprint()) + " " + pk.getAlgorithm() + " " + Long.toHexString(pk.getKeyID()));
        }*/

        publicOut.close();
    }

    public static void exportSecretKey(
            OutputStream secretOut,
            KeyPair dsaKp,
            KeyPair elgKp,
            String identity,
            char[] passPhrase,
            boolean armor, Date d)
            throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException, NoSuchAlgorithmException {
        if (armor) {
            secretOut = new ArmoredOutputStream(secretOut);
        }

        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, d);

        System.out.println("public keypair :" + UtilHex.toHex(dsaKeyPair.getPublicKey().getEncoded()));
        PGPKeyPair elgKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, d);
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
                identity, sha1Calc, null, null, new JcaPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase));

        keyRingGen.addSubKey(elgKeyPair);

        keyRingGen.generateSecretKeyRing().encode(secretOut);
        //System.out.println("Public Key: algorithm-> " + dsaKeyPair.getPublicKey().getAlgorithm() + " bit strength-> " + dsaKeyPair.getPublicKey().getBitStrength() + " creation time-> " + dsaKeyPair.getPublicKey().getCreationTime() + " fingerprint-> " + UtilHex.toHex(dsaKeyPair.getPublicKey().getFingerprint()) + " key id-> " + dsaKeyPair.getPublicKey().getKeyID() + " key len-> " + UtilHex.toHex(dsaKeyPair.getPublicKey().getEncoded()).length() + " ");

        secretOut.close();

        System.out.println("zatvorio sam");
        if (armor) {
            //publicOut = new ArmoredOutputStream(publicOut);
        }

        //keyRingGen.generatePublicKeyRing().encode(publicOut);
        //Iterator<PGPPublicKey> it = keyRingGen.generatePublicKeyRing().iterator();
        /*while (it.hasNext()) {
            PGPPublicKey pk = it.next();
            System.out.println("key public: " + UtilHex.toHex(pk.getFingerprint()) + " " + pk.getAlgorithm() + " " + UtilHex.toHex(pk.getEncoded()).length());
        }
         */
        //publicOut.close();
    }

    private static String get_key_id_format(String key_id) {
        key_id = key_id.toUpperCase();
        return key_id.substring(0, 4) + " " + key_id.substring(4, 8) + " " + key_id.substring(8, 12) + " " + key_id.substring(12, 16);
    }

    public static void add_private_key(MyMasterKey mk, MySubKey sk) {
        try {

            StringBuilder sb = new StringBuilder();

            //dsa master key
            sb.append(mk.getValid_from()).append(" ");
            sb.append(mk.getName()).append("<").append(mk.getEmail()).append("> endname ");
            sb.append(mk.getKey_id()).append(" ");
            sb.append(mk.getPublic_key()).append(" ");
            sb.append("DSA ");
            sb.append(mk.getPrivate_key()).append(" \n");

            //elgamal sub key
            sb.append(sk.getValid_from()).append(" ");
            sb.append(sk.getName()).append("<").append(sk.getEmail()).append("> endname ");
            sb.append(sk.getKey_id()).append(" ");
            sb.append(sk.getPublic_key()).append(" ");
            sb.append("ELGAMAL ");
            sb.append(sk.getPrivate_key()).append(" ");
            sb.append(sk.getMaster_key_id()).append(" \n");

            Files.write(Paths.get(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//private_keyring.txt"), sb.toString().getBytes(), StandardOpenOption.APPEND);
        } catch (IOException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public static void add_public_key(MyMasterKey mk, MySubKey sk) {
        try {

            StringBuilder sb = new StringBuilder();

            //dsa master key
            sb.append(mk.getValid_from()).append(" ");
            sb.append(mk.getName()).append("<").append(mk.getEmail()).append("> endname ");
            sb.append(mk.getKey_id()).append(" ");
            sb.append(mk.getPublic_key()).append(" ");
            sb.append("DSA \n");

            //elgamal sub key
            sb.append(sk.getValid_from()).append(" ");
            sb.append(sk.getName()).append("<").append(sk.getEmail()).append("> endname ");
            sb.append(sk.getKey_id()).append(" ");
            sb.append(sk.getPublic_key()).append(" ");
            sb.append("ELGAMAL ");
            sb.append(sk.getMaster_key_id()).append(" \n");

            Files.write(Paths.get(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//public_keyring.txt"), sb.toString().getBytes(), StandardOpenOption.APPEND);
        } catch (IOException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public static void remove_key(String key_id, int row_index) {
        try {

            DefaultTableModel model = (DefaultTableModel) central_table.getModel();
            model.removeRow(row_index);

            master_keys.remove(row_index);
            sub_keys.remove(row_index);

            File public_keyring = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp/public_keyring.txt");

            Scanner in = new Scanner(new InputStreamReader(new FileInputStream(public_keyring.getAbsolutePath()), StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();

            String line;
            while (in.hasNext()) {
                line = in.nextLine();
                String test = line.substring(line.indexOf("endname"), line.length());
                String[] data = test.split(" ");
                if (!data[1].equals(key_id)) {
                    System.out.println("Isto je sve: " + data[0] + " " + data[1] + " " + data[2]);
                    sb.append(line).append("\n");
                    line = in.nextLine();
                    sb.append(line).append("\n");
                } else {

                    line = in.nextLine();
                }
            }

            in.close();

            System.out.println(sb.toString());

            public_keyring.delete();

            public_keyring.createNewFile();
            Files.write(Paths.get(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//public_keyring.txt"), sb.toString().getBytes(), StandardOpenOption.WRITE);

        } catch (FileNotFoundException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static int num_private_keys(List<MyMasterKey> list) {
        int k = 0;
        for (int i = 0; i < list.size(); i++) {
            if (list.get(i).isPr_key()) {
                k++;
            }
        }
        return k;
    }

    private static int num_public_keys(List<MyMasterKey> list) {
        int k = 0;
        for (int i = 0; i < list.size(); i++) {
            if (!list.get(i).isPr_key()) {
                k++;
            }
        }
        return k;
    }
}
