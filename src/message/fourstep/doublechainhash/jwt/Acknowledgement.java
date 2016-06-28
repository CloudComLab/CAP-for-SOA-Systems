package message.fourstep.doublechainhash.jwt;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import message.JsonWebToken;
import message.MessageType;

/**
 *
 * @author Scott
 */
public class Acknowledgement extends JsonWebToken {
    private static final long serialVersionUID = 20160628L;
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
