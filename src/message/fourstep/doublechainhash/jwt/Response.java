package message.fourstep.doublechainhash.jwt;

import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

import message.JsonWebToken;
import message.MessageType;

/**
 *
 * @author Scott
 */
public class Response extends JsonWebToken {
    private static final long serialVersionUID = 20160628L;
    private final Request request;
    private final String clientDeviceLastChainHash; // ACKj
    private final String userLastChainHash; // Ri-1
    
    public Response(Request req, String hash1, String hash2) {
        super(MessageType.Response);
        
        this.request = req;
        this.clientDeviceLastChainHash = hash1;
        this.userLastChainHash = hash2;
        
        super.add2Body(MessageType.Request.name(), request.toString());
        super.add2Body("result", clientDeviceLastChainHash);
        super.add2Body("chainhash", userLastChainHash);
    }
    
    public Response(String rStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(rStr, publicKey);
        
        this.clientDeviceLastChainHash = String.valueOf(bodyContents.get("result"));
        this.userLastChainHash = String.valueOf(bodyContents.get("chainhash"));
        this.request = new Request(
                String.valueOf(bodyContents.get(MessageType.Request.name())),
                null);
    }
    
    public Request getRequest() {
        return request;
    }
    
    public String getClientDeviceLastChainHash() {
        return clientDeviceLastChainHash;
    }
    
    public String getUserLastChainHash() {
        return userLastChainHash;
    }
}
