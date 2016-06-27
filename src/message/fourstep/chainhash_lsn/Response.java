package message.fourstep.chainhash_lsn;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import message.MessageType;
import message.SOAPMessage;

/**
 *
 * @author Scott
 */
public class Response extends SOAPMessage {
    private static final long serialVersionUID = 20160627L;
    private final Request request;
    private final String result;
    private final String lastChainHash;
    
    public Response(Request req, String result, String hash) {
        super(MessageType.Response);
        
        this.request = req;
        this.result = result;
        this.lastChainHash = hash;
        
        super.add2Body(MessageType.Request.name(), request.toString());
        super.add2Body("result", result);
        super.add2Body("chainhash", lastChainHash);
    }
    
    public Response(String rStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(rStr, publicKey);
        
        this.result = String.valueOf(bodyContents.get("result"));
        this.lastChainHash = String.valueOf(bodyContents.get("chainhash"));
        this.request = new Request(
                String.valueOf(bodyContents.get(MessageType.Request.name())),
                null);
    }
    
    public Request getRequest() {
        return request;
    }
    
    // for C&L
    public String getResult() {
        return result;
    }
    
    // for DC&L
    public String getClientLastChainHash() {
        return result;
    }
    
    public String getChainHash() {
        return lastChainHash;
    }
}
