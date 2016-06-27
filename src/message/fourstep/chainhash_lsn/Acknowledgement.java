package message.fourstep.chainhash_lsn;

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
    private final ReplyResponse replyResponse;
    
    public Acknowledgement(String result, ReplyResponse rr) {
        super(MessageType.Acknowledgement);
        
        this.result = result;
        this.replyResponse = rr;
        
        super.add2Body("result", result);
        super.add2Body(MessageType.ReplyResponse.name(), replyResponse.toString());
    }
    
    public Acknowledgement(String ackStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(ackStr, publicKey);
        
        this.result = String.valueOf(bodyContents.get("result"));
        this.replyResponse = new ReplyResponse(
                String.valueOf(bodyContents.get(MessageType.ReplyResponse.name())),
                null);
    }
    
    public String getResult() {
        return result;
    }
    
    public ReplyResponse getReplyResponse() {
        return replyResponse;
    }
}
