package utility;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import service.SocketServer;

public class Utils {
    private static final int BUF_SIZE = 8192;
    private static final String HEX = "0123456789ABCDEF";
    
    /**
     * Converts byte array into hexadecimal string.
     */
    public static String Hex2Str(byte[] bytes) {
        String str = "";
        
        for (byte b: bytes) {
            int v = b & 0xFF;

            str += HEX.charAt(v >> 4) + "" + HEX.charAt(v & 0xF);
        }
        
        return str;
    }
    
    /**
     * Converts hexadecimal string into byte array.
     */
    public static byte[] Str2Hex(String str) {
        byte[] bytes = new byte[str.length() / 2];
        
        byte b;
        
        for (int i = 0; i < str.length(); i += 2) {
            b = (byte) (HEX.indexOf(str.charAt(i)) << 4);
            b += (byte) (HEX.indexOf(str.charAt(i + 1)));
            
            bytes[i / 2] = b;
        }
        
        return bytes;
    }
    
    /**
     * Sends data through the DataOutputStream by converting into UTF-8 bytes.
     */
    public static void send(DataOutputStream out, String data) {
        try {
            byte[] bytes = data.getBytes("UTF-8");
            
            out.writeInt(bytes.length);
            out.write(bytes);
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Reads the file and sends it through the DataOutputStream.
     */
    public static void send(DataOutputStream out, File file) {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buf = new byte[BUF_SIZE];
            int n;
            
            out.writeLong(file.length());
            
            while ((n = fis.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
        } catch (IOException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Receives a UTF-8 string from DataInputStream
     */
    public static String receive(DataInputStream in) {
        String data = "";
        
        try {
            byte[] bytes = new byte[in.readInt()];
            
            in.readFully(bytes);
            
            data = new String(bytes, "UTF-8");
        } catch (IOException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return data;
    }
    
    /**
     * Receives a file from DataInputStream.
     */
    public static void receive(DataInputStream in, File file) {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            byte[] buf = new byte[BUF_SIZE];
            int n;
            
            for (long leftBytes = in.readLong(); leftBytes > 0; leftBytes -= n) {
                n = in.read(buf);
                fos.write(buf, 0, n);
            }
        } catch (IOException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Digest a file with a specific algorithm.
     * @return the digest value
     */
    public static String digest(File file, String algorithm) {
        try (InputStream fis = new FileInputStream(file)) {
            int n;
            byte[] buffer = new byte[BUF_SIZE];
            MessageDigest digest = MessageDigest.getInstance(algorithm);

            while ((n = fis.read(buffer)) > 0) {
                digest.update(buffer, 0, n);
            }
            
            return Hex2Str((digest.digest()));
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException | IOException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        }

        return String.format("[cannot digest %s]", file.getName());
    }
    
    /**
     * Generates a KeyPair randomly.
     */
    public static KeyPair randomGenerateKeyPair() {
        KeyPair keyPair = null;
        
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(512, new SecureRandom());
            keyPair = keyGen.generateKeyPair();
        } catch (SecurityException | NoSuchAlgorithmException ex) {
            Logger.getLogger(SocketServer.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return keyPair;
    }
    
    /**
     * Reads KeyPair from specific file.
     */
    public static KeyPair readKeyPair(String fname) {
        File file = new File("keypair/" + fname);
        
        try (FileInputStream fis = new FileInputStream(file);
             ObjectInputStream in = new ObjectInputStream(fis)) {
            return (KeyPair) in.readObject();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | ClassNotFoundException ex) {
            Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return null;
    }
    
    public static void main(String[] args) {
        String[] keyFileNames = {"keypair/client.key", "keypair/service_provider.key"};
        
        for (String fname : keyFileNames) {
            File keyFile = new File(fname);
            
            if (!keyFile.exists()) {
                try {
                    keyFile.createNewFile();
                } catch (IOException ex) {
                    Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            
            try (FileOutputStream fos = new FileOutputStream(fname);
                 ObjectOutputStream out = new ObjectOutputStream(fos)) {
                out.writeObject(randomGenerateKeyPair());
            } catch (FileNotFoundException ex) {
                Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(Utils.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
}
