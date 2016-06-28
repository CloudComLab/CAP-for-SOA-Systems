package service.handler;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.net.Socket;
import java.security.SignatureException;
import java.util.concurrent.locks.ReentrantLock;

import message.noncap.*;
import message.Operation;
import service.Config;
import service.Key;
import utility.Utils;

/**
 *
 * @author Scott
 */
public class NonCAPHandler extends ConnectionHandler {
    public static final File REQ_ATTESTATION;
    public static final File ACK_ATTESTATION;
    
    private static final ReentrantLock LOCK;
    
    static {
        REQ_ATTESTATION = new File(Config.ATTESTATION_DIR_PATH + "/service-provider/noncap.req");
        ACK_ATTESTATION = new File(Config.ATTESTATION_DIR_PATH + "/service-provider/noncap.ack");
        
        LOCK = new ReentrantLock();
    }
    
    public NonCAPHandler(Socket socket, Key key) {
        super(socket, key);
    }
    
    @Override
    protected void handle(DataOutputStream out, DataInputStream in)
            throws SignatureException, IllegalAccessException {
        LOCK.lock();
        
        try {
            Request req = new Request(Utils.receive(in), null);
            
            String result;
            
            Operation op = req.getOperation();
            
            File file = new File(Config.DATA_DIR_PATH + '/' + op.getPath());
            boolean sendFileAfterAck = false;

            switch (op.getType()) {
                case UPLOAD:
                    file = new File(Config.DOWNLOADS_DIR_PATH + '/' + op.getPath());
                    
                    Utils.receive(in, file);

                    String digest = Utils.digest(file, Config.DIGEST_ALGORITHM);

                    if (op.getMessage().equals(digest)) {
                        result = "ok";
                    } else {
                        result = "upload fail";
                    }
                    
                    Utils.writeDigest(file.getPath(), digest);

                    break;
                case DOWNLOAD:
                    result = Utils.readDigest(file.getPath());
                    
                    sendFileAfterAck = true;
                    
                    break;
                case AUDIT:
                    result = Utils.readDigest(REQ_ATTESTATION.getPath());
                    result += Utils.readDigest(ACK_ATTESTATION.getPath());
                    
                    sendFileAfterAck = true;
                    
                    break;
                default:
                    result = "operation type mismatch";
            }
            
            Acknowledgement ack = new Acknowledgement(result);
            
            Utils.send(out, ack.toString());
            
            if (sendFileAfterAck) {
                switch (op.getType()) {
                    case DOWNLOAD:
                        Utils.send(out, file);
                        
                        break;
                    case AUDIT:
                        Utils.send(out, REQ_ATTESTATION);
                        Utils.send(out, ACK_ATTESTATION);
                        
                        break;
                }
            }
            
            Utils.appendAndDigest(REQ_ATTESTATION, req.toString() + '\n');
            Utils.appendAndDigest(ACK_ATTESTATION, ack.toString() + '\n');
        } finally {
            if (LOCK != null) {
                LOCK.unlock();
            }
        }
    }
}
