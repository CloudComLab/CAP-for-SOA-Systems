package message.fourstep.chainhash_lsn.jwt;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import message.JsonWebToken;
import message.MessageType;

/**
 *
 * @author Scott
 */
public class ReplyResponse extends JsonWebToken {
    private static final long serialVersionUID = 20160628L;
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