package message.noncap;

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
