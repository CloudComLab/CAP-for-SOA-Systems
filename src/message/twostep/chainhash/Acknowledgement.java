package message.twostep.chainhash;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import message.MessageType;
import message.SOAPMessage;

/**
 *
 * @author Scott
 */
public class Acknowledgement extends SOAPMessage {
    private static final long serialVersionUID = 20160627L;
    private final String result;
    private final String lastChainHash;
    private final Request request;
    
    public Acknowledgement(String result, String hash, Request req) {
        super(MessageType.Acknowledgement);
        
        this.result = result;
        this.lastChainHash = hash;
        this.request = req;
        
        super.add2Body("result", result);
        super.add2Body("chainhash", lastChainHash);
        super.add2Body(MessageType.Request.name(), req.toString());
    }
    
    public Acknowledgement(String ackStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(ackStr, publicKey);
        
        this.result = String.valueOf(bodyContents.get("result"));
        this.lastChainHash = String.valueOf(bodyContents.get("chainhash"));
        this.request = new Request(
                String.valueOf(bodyContents.get(MessageType.Request.name())),
                null);
    }
    
    public String getResult() {
        return result;
    }
    
    public Request getRequest() {
        return request;
    }
    
    public String getChainHash() {
        return lastChainHash;
    }
}
