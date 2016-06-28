package message.fourstep.doublechainhash.jwt;

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
    private final String clientID;
    
    public Request(Operation op, String id) {
        super(MessageType.Request);
        
        this.operation = op;
        this.clientID = id;
        
        super.add2Body("operation", operation.toMap());
        super.add2Body("client-id", clientID);
    }
    
    public Request(String qStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(qStr, publicKey);
        
        this.operation = new Operation((Map) bodyContents.get("operation"));
        this.clientID = String.valueOf(bodyContents.get("client-id"));
    }
    
    public Operation getOperation() {
        return operation;
    }
    
    public String getClientID() {
        return clientID;
    }
}
