package client;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.Socket;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import message.Operation;
import message.OperationType;
import message.fourstep.doublechainhash.*;
import service.Config;
import service.handler.fourstep.DoubleChainHashHandler;
import service.DoubleHashingChainTable;
import service.Key;
import utility.Utils;

/**
 *
 * @author Scott
 */
public class DoubleChainHashClient extends Client {
    private static final File ATTESTATION;
    private static final Logger LOGGER;
    
    static {
        ATTESTATION = new File(Config.ATTESTATION_DIR_PATH + "/client/doublechainhash");
        LOGGER = Logger.getLogger(DoubleChainHashClient.class.getName());
    }
    
    private final String id;
    private String lastChainHash;
    
    public DoubleChainHashClient(String id, Key cliKey, Key spKey) {
        super(Config.SERVICE_HOSTNAME,
              Config.DOUBLECHAINHASH_SERVICE_PORT,
              cliKey,
              spKey,
              true);
        
        this.id = id;
        this.lastChainHash = Config.INITIAL_HASH;
    }
    
    public String getLastChainHash() {
        return lastChainHash;
    }
    
    @Override
    protected void handle(Operation op, Socket socket, DataOutputStream out, DataInputStream in)
            throws SignatureException, IllegalAccessException {
        Request req = new Request(op, op.getClientID());
        
        req.sign(clientKeyPair, clientKeyInfo);

        Utils.send(out, req.toString());

        Response res = new Response(
                Utils.receive(in),
                (RSAPublicKey) serviceProviderKeyPair.getPublic());

        String result = null;

        if (!lastChainHash.equals(res.getClientDeviceLastChainHash())) {
            result = "chain hash mismatch";
        }

        ReplyResponse rr = new ReplyResponse(res);

        rr.sign(clientKeyPair, clientKeyInfo);

        Utils.send(out, rr.toString());

        if (op.getType() == OperationType.UPLOAD) {
            Utils.send(out, new File(Config.DATA_DIR_PATH + '/' + op.getPath()));
        }

        Acknowledgement ack = new Acknowledgement(
                Utils.receive(in),
                (RSAPublicKey) serviceProviderKeyPair.getPublic());

        if (result == null) {
            result = ack.getResult();
        }
        
        String fname = "";

        switch (op.getType()) {
            case DOWNLOAD:
                fname = "-" + System.currentTimeMillis();
            case AUDIT:
                fname = String.format("%s/%s%s",
                            Config.DOWNLOADS_DIR_PATH,
                            op.getPath(),
                            fname);

                File file = new File(fname);

                Utils.receive(in, file);

                String digest = Utils.digest(file);

                if (ack.getResult().equals(digest)) {
                    result = "download success";
                } else {
                    result = "download file digest mismatch";
                }

                break;
        }

        lastChainHash = Utils.digest(ack.toString());

        synchronized (this) {
            Utils.write(ATTESTATION, ack.toString());
        }
    }
    
    @Override
    public String getHandlerAttestationPath() {
        return DoubleChainHashHandler.ATTESTATION.getPath();
    }

    @Override
    public boolean audit(File spFile) {
        boolean success = true;
        RSAPublicKey spKey = (RSAPublicKey) serviceProviderKeyPair.getPublic();
        
        DoubleHashingChainTable hashingChainTab = new DoubleHashingChainTable();
        Map<String, String> mainChainTab = new HashMap<>();
        
        try (FileReader fr = new FileReader(spFile);
             BufferedReader br = new BufferedReader(fr)) {
            do {
                String s = br.readLine();
                
                if (s == null) {
                    break;
                }
                
                Acknowledgement ack = new Acknowledgement(s, spKey);
                ReplyResponse rr = ack.getReplyResponse();
                Response res = rr.getResponse();
                Request req = res.getRequest();
                
                String clientID = req.getClientID();
                
                mainChainTab.put(res.getUserLastChainHash(), Utils.digest(res.toString()));
                
                if (hashingChainTab.getLastChainHash(clientID).equals(
                    res.getClientDeviceLastChainHash())) {
                    hashingChainTab.chain(clientID, Utils.digest(ack.toString()));
                } else {
                    success = false;
                }
            } while (success);
            
            String hash = Config.INITIAL_HASH;
            int numFound = 0;
            
            while (mainChainTab.containsKey(hash)) {
                numFound += 1;
                
                hash = mainChainTab.get(hash);
            }
            
            success &= numFound == mainChainTab.size();
        } catch (SignatureException | IOException ex) {
            success = false;
            
            LOGGER.log(Level.SEVERE, null, ex);
        }
        
        return success;
    }
}
