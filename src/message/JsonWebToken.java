package message;

import java.security.KeyPair;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

/**
 *
 * @author Scott
 */
public class JsonWebToken extends CAPMessage {
    private JsonWebSignature jws;
    private JwtClaims body;
    private boolean dirty;
    
    public JsonWebToken(MessageType type) {
        super(type);
        
        jws = new JsonWebSignature();
        body = new JwtClaims();
        
        body.setSubject(type.name());
        jws.setPayload(body.toJson());
        
        dirty = false;
    }
    
    /**
     * Parse the JWT string into claims and validate its signature by
     * the public key. If the public key is not given, the verification will
     * be skipped.
     * 
     * @throws SignatureException if the signature is invalid.
     */
    public JsonWebToken(String jwtString, RSAPublicKey validatePublicKey)
            throws SignatureException {
        super(jwtString, validatePublicKey);
        
        jws = new JsonWebSignature();
        try {
            body = JsonWebToken.parseJWT(jwtString, validatePublicKey);
        } catch (InvalidJwtException e) {
            throw new SignatureException(e.getMessage());
        }
        
        jws.setPayload(body.toJson());
        
        dirty = false;
    }
    
    @Override
    public void add2Body(String name, String value) {
        body.setClaim(name, value);
        
        dirty = true;
    }
    
    @Override
    public void add2Body(String name, Map<String, String> content) {
        for (Entry<String, String> entry: content.entrySet()) {
            add2Body(entry.getKey(), entry.getValue());
        }
    }
    
    @Override
    public void sign(KeyPair keyPair, Map<String, String> options) {
        if (options == null) {
            throw new NullPointerException("options cannot be null!");
        }
        
        sign((RSAPrivateKey) keyPair.getPrivate(),
             options.get("keyId"),
             options.get("signMethod"));
    }
    
    /**
     * Sign this JSON web token with the specific key and signing method.
     */
    public void sign(RSAPrivateKey privateKey, String keyId, String signMethod) {
        jws.setKey(privateKey);
        jws.setKeyIdHeaderValue(keyId);
        jws.setAlgorithmHeaderValue(signMethod);
    }
    
    @Override
    public String toString() {
        try {
            if (dirty) {
                jws.setPayload(body.toJson());
                
                dirty = false;
            }
            
            return jws.getCompactSerialization();
        } catch (JoseException ex) {
            Logger.getLogger(JsonWebToken.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return "[toString failed]";
    }
    
    public static JwtClaims parseJWT(String jwt, RSAPublicKey publicKey)
            throws InvalidJwtException {
        JwtConsumerBuilder builder = new JwtConsumerBuilder();
        
        builder.setRequireSubject();
        
        if (publicKey != null) {
            builder.setVerificationKey(publicKey);
        }
        
        return builder.build().processToClaims(jwt);
    }
}
