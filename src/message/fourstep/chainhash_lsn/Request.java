package message.fourstep.chainhash_lsn;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import message.MessageType;
import message.Operation;
import message.SOAPMessage;

/**
 *
 * @author Scott
 */
public class Request extends SOAPMessage {
    private static final long serialVersionUID = 20160627L;
    private final Operation operation;
    private final String clientID;
    private final Integer localSequenceNumber;
    
    public Request(Operation op, String id, Integer lsn) {
        super(MessageType.Request);
        
        this.operation = op;
        this.clientID = id;
        this.localSequenceNumber = lsn;
        
        super.add2Body("operation", operation.toMap());
        super.add2Body("client-id", clientID);
        super.add2Body("lsn", localSequenceNumber.toString());
    }
    
    public Request(String qStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(qStr, publicKey);
        
        this.operation = new Operation((Map) bodyContents.get("operation"));
        this.clientID = String.valueOf(bodyContents.get("client-id"));
        this.localSequenceNumber = Integer.decode(String.valueOf(bodyContents.get("lsn")));
    }
    
    public Operation getOperation() {
        return operation;
    }
    
    public String getClientID() {
        return clientID;
    }
    
    public Integer getLocalSequenceNumber() {
        return localSequenceNumber;
    }
}
