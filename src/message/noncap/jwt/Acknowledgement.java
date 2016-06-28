package message.noncap.jwt;

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
    
    public Acknowledgement(String result) {
        super(MessageType.Acknowledgement);
        
        this.result = result;
        
        super.add2Body("result", result);
    }
    
    public Acknowledgement(String ackStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(ackStr, publicKey);
        
        this.result = String.valueOf(bodyContents.get("result"));
    }
    
    public String getResult() {
        return result;
    }
}
