package service.handler;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyPair;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Map;

import client.Client;
import service.Key;
import service.KeyManager;

/**
 *
 * @author Scott
 */
public abstract class ConnectionHandler implements Runnable {
    private static final Logger LOGGER;
    
    static {
        LOGGER = Logger.getLogger(Client.class.getName());
    }
    
    protected final Socket socket;
    protected final KeyPair keyPair;
    protected final Map<String, String> keyInfo;
    
    public ConnectionHandler(Socket socket, Key key) {
        this.socket = socket;
        
        KeyManager keyManager = KeyManager.getInstance();
        this.keyPair = keyManager.getKeyPair(key);
        this.keyInfo = keyManager.getKeyInfo(key);
    }
    
    protected abstract void handle(DataOutputStream out, DataInputStream in)
            throws SignatureException, IllegalAccessException;
    
    @Override
    public void run() {
        try (DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             DataInputStream in = new DataInputStream(socket.getInputStream())) {
            handle(out, in);
            
            socket.close();
        } catch (IOException | SignatureException | IllegalAccessException ex) {
            LOGGER.log(Level.SEVERE, null, ex);
        }
    }
}
