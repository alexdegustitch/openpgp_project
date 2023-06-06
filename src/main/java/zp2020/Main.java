/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package zp2020;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFrame;
import javax.swing.filechooser.FileSystemView;

/**
 *
 * @author Aleksandar
 */
public class Main {

    public Main() {

        //ako nema foldera zp, napravi ga
        new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp").mkdirs();

        File f = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp//zp_keys");

        f.mkdirs();
        Path path = Paths.get(f.getAbsolutePath());
        try {
            Files.setAttribute(path, "dos:hidden", Boolean.TRUE, LinkOption.NOFOLLOW_LINKS);
        } catch (IOException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }

        File ring_private_keys = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp/private_keyring.txt");

        if (!ring_private_keys.exists()) {
            try {
                ring_private_keys.createNewFile();
            } catch (IOException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        File ring_public_keys = new File(FileSystemView.getFileSystemView().getHomeDirectory() + "//zp/public_keyring.txt");

        if (!ring_public_keys.exists()) {
            try {
                ring_public_keys.createNewFile();
            } catch (IOException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        JFrame frame = Utils.get_frame();

    }

    public static void main(
            String[] args) {

        new Main();
    }

}
