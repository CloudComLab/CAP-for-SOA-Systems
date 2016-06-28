package message.noncap.jwt;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import message.JsonWebToken;
import message.MessageType;
import message.Operation;

/**
 *
 * @author Scott
 */
public class Request extends JsonWebToken {
    private static final long serialVersionUID = 20160628L;
    private final Operation operation;
    
    public Request(Operation op) {
        super(MessageType.Request);
        
        this.operation = op;
        
        super.add2Body("operation", operation.toMap());
    }
    
    public Request(String qStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(qStr, publicKey);
        
        this.operation = new Operation((Map) bodyContents.get("operation"));
    }
    
    public Operation getOperation() {
        return operation;
    }
}
