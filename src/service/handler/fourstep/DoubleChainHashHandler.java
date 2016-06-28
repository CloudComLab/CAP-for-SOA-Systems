package service.handler.fourstep;

import service.DoubleHashingChainTable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.net.Socket;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import message.Operation;
import message.fourstep.doublechainhash.*;
import service.Config;
import service.Key;
import service.KeyManager;
import service.handler.ConnectionHandler;
import utility.Utils;

/**
 *
 * @author Scott
 */
public class DoubleChainHashHandler extends ConnectionHandler {
    public static final File ATTESTATION;
    
    private static final DoubleHashingChainTable HASHING_CHAIN_TABLE;
    private static final ReentrantLock LOCK;
    
    static {
        ATTESTATION = new File(Config.ATTESTATION_DIR_PATH + "/service-provider/doublechainhash");
        
        HASHING_CHAIN_TABLE = new DoubleHashingChainTable();
        LOCK = new ReentrantLock();
    }
    
    public DoubleChainHashHandler(Socket socket, Key key) {
        super(socket, key);
    }
    
    @Override
    protected void handle(DataOutputStream out, DataInputStream in)
            throws SignatureException, IllegalAccessException {
        KeyManager keyManager = KeyManager.getInstance();
        RSAPublicKey clientPubKey = (RSAPublicKey) keyManager.getPublicKey(Key.CLIENT);
        Lock lock = null;
        
        try {
            Request req = new Request(Utils.receive(in), clientPubKey);
            String result, clientID;
            
            LOCK.lock();
            try {
                clientID = req.getClientID();

                String lastChainHash = HASHING_CHAIN_TABLE.getLastChainHash(clientID);
                String lastChainHashOfAll = HASHING_CHAIN_TABLE.getLastChainHashOfAll();

                Response res = new Response(req, lastChainHash, lastChainHashOfAll);

                res.sign(keyPair, keyInfo);

                Utils.send(out, res.toString());

                HASHING_CHAIN_TABLE.chain(Utils.digest(res.toString()));
            } finally {
                LOCK.unlock();
            }
            
            ReplyResponse rr = new ReplyResponse(Utils.receive(in), clientPubKey);
            
            Operation op = req.getOperation();

            File file = new File(Config.DATA_DIR_PATH + '/' + op.getPath());
            ReentrantReadWriteLock rwl = service.File.parse(op.getPath()).getLock();
            
            switch (op.getType()) {
                case UPLOAD:
                case AUDIT:
                    lock = rwl.writeLock();
                    lock.lock();
                    
                    break;
                case DOWNLOAD:
                    lock = rwl.readLock();
                    lock.lock();
                    
                    break;
            }
            
            boolean sendFileAfterAck = false;
            
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
            
            Acknowledgement ack = new Acknowledgement(result, rr);
            
            ack.sign(keyPair, keyInfo);
            
            String ackStr = ack.toString();
            
            Utils.send(out, ackStr);
            
            if (sendFileAfterAck) {
                Utils.send(out, file);
            }
            
            HASHING_CHAIN_TABLE.chain(clientID, Utils.digest(ackStr));
            
            Utils.appendAndDigest(ATTESTATION, ackStr + '\n');
        } finally {
            if (lock != null) {
                lock.unlock();
            }
        }
    }
}
