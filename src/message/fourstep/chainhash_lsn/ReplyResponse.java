package message.fourstep.chainhash_lsn;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import message.MessageType;
import message.SOAPMessage;

/**
 *
 * @author Scott
 */
public class ReplyResponse extends SOAPMessage {
    private static final long serialVersionUID = 20160627L;
    private final Response response;
    
    public ReplyResponse(Response res) {
        super(MessageType.ReplyResponse);
        
        this.response = res;
        
        super.add2Body(MessageType.Response.name(), response.toString());
    }
    
    public ReplyResponse(String rrStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(rrStr, publicKey);
        
        this.response = new Response(
                String.valueOf(bodyContents.get(MessageType.Response.name())),
                null);
    }
    
    public Response getResponse() {
        return response;
    }
}