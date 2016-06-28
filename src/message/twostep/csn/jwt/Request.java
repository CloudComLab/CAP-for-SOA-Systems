package message.twostep.csn.jwt;

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
    private final Integer consecutiveSequenceNumber;
    
    public Request(Operation op, Integer csn) {
        super(MessageType.Request);
        
        this.operation = op;
        this.consecutiveSequenceNumber = csn;
        
        super.add2Body("operation", operation.toMap());
        super.add2Body("CSN", consecutiveSequenceNumber.toString());
    }
    
    public Request(String qStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(qStr, publicKey);
        
        String csn = String.valueOf(bodyContents.get("CSN"));
        
        this.operation = new Operation((Map) bodyContents.get("operation"));
        this.consecutiveSequenceNumber = Integer.parseInt(csn);
    }
    
    public Operation getOperation() {
        return operation;
    }
    
    public Integer getConsecutiveSequenceNumber() {
        return consecutiveSequenceNumber;
    }
}
