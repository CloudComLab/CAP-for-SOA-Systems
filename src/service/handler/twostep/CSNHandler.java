package service.handler.twostep;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.net.Socket;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.locks.ReentrantLock;

import message.Operation;
import message.twostep.csn.*;
import service.Config;
import service.Key;
import service.KeyManager;
import service.handler.ConnectionHandler;
import utility.Utils;

/**
 *
 * @author Scott
 */
public class CSNHandler extends ConnectionHandler {
    public static final File ATTESTATION;
    
    private static final ReentrantLock LOCK;
    private static int CSN;
    
    static {
        ATTESTATION = new File(Config.ATTESTATION_DIR_PATH + "/service-provider/csn");
        
        LOCK = new ReentrantLock();
        CSN = 0;
    }
    
    public CSNHandler(Socket socket, Key key) {
        super(socket, key);
    }
    
    @Override
    protected void handle(DataOutputStream out, DataInputStream in)
            throws SignatureException, IllegalAccessException {
        KeyManager keyManager = KeyManager.getInstance();
        RSAPublicKey clientPubKey = (RSAPublicKey) keyManager.getPublicKey(Key.CLIENT);
        
        LOCK.lock();
        
        try {
            Request req = new Request(Utils.receive(in), clientPubKey);
            
            String result;
            
            Operation op = req.getOperation();
            
            File file = new File(Config.DATA_DIR_PATH + '/' + op.getPath());
            boolean sendFileAfterAck = false;
            
            if (req.getConsecutiveSequenceNumber() == CSN + 1) {
                CSN += 1;
                
                switch (op.getType()) {
                    case UPLOAD:
                        file = new File(Config.DOWNLOADS_DIR_PATH + '/' + op.getPath());
                        
                        Utils.receive(in, file);
                        
                        String digest = Utils.digest(file);
                        
                        if (op.getMessage().equals(digest)) {
                            result = "ok";
                        } else {
                            result = "upload fail";
                        }
                        
                        Utils.writeDigest(file.getPath(), digest);
                        
                        break;
                    case AUDIT:
                        file = new File(op.getPath());
                        
                        result = Utils.readDigest(file.getPath());
                        
                        sendFileAfterAck = true;
                        
                        break;
                    case DOWNLOAD:
                        result = Utils.readDigest(file.getPath());
                        
                        sendFileAfterAck = true;
                        
                        break;
                    default:
                        result = "operation type mismatch";
                }
            } else {
                result = "CSN mismatch";
            }
            
            Acknowledgement ack = new Acknowledgement(result, req);
            
            ack.sign(keyPair, keyInfo);
            
            Utils.send(out, ack.toString());
            
            if (sendFileAfterAck) {
                Utils.send(out, file);
            }
            
            Utils.appendAndDigest(ATTESTATION, ack.toString() + '\n');
        } finally {
            if (LOCK != null) {
                LOCK.unlock();
            }
        }
    }
}
