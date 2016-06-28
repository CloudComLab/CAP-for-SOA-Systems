package message;

import java.io.Serializable;
import java.security.KeyPair;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 *
 * @author Scott
 */
public abstract class CAPMessage implements Serializable {
    protected String originMessage;
    protected MessageType messageType;
    protected Map bodyContents;
    
    public CAPMessage(MessageType type) {
        messageType = type;
        
        bodyContents = new LinkedHashMap();
    }
    
    public CAPMessage(String message, RSAPublicKey publicKey)
            throws SignatureException {
        originMessage = message;
        
        bodyContents = new LinkedHashMap();
    }
    
    protected abstract void initContents();
    
    public abstract void add2Body(String name, String value);
    
    public abstract void add2Body(String name, Map<String, String> contents);
    
    public abstract void sign(KeyPair keyPair, Map<String, String> options);
    
    @Override
    public abstract String toString();
}
