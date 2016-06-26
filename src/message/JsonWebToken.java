package message;

import java.io.Serializable;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

/**
 *
 * @author Scott
 */
public class JsonWebToken implements Serializable {
    private JsonWebSignature jws;
    private JwtClaims body;
    private boolean dirty;
    
    public JsonWebToken(MessageType type) {
        jws = new JsonWebSignature();
        body = new JwtClaims();
        
        body.setSubject(type.name());
        jws.setPayload(body.toJson());
        
        dirty = false;
    }
    
    public JsonWebToken(String jwtString, RSAPublicKey validatePublicKey)
            throws InvalidJwtException {
        jws = new JsonWebSignature();
        body = JsonWebToken.parseJWT(jwtString, validatePublicKey);
        
        jws.setPayload(body.toJson());
        
        dirty = false;
    }
    
    public void add2Body(String name, String value) {
        body.setClaim(name, value);
        
        dirty = true;
    }
    
    public void add2Body(LinkedHashMap<String, String> map) {
        for (Entry<String, String> entry: map.entrySet()) {
            add2Body(entry.getKey(), entry.getValue());
        }
    }
    
    /**
     * Sign this JSON web token with the specific key through RS256.
     */
    public void sign(RsaJsonWebKey keyPair) {
        sign(keyPair, AlgorithmIdentifiers.RSA_USING_SHA256);
    }
    
    /**
     * Sign this JSON web token with the specific key and signing method.
     */
    public void sign(RsaJsonWebKey keyPair, String signMethod) {
        jws.setKeyIdHeaderValue(keyPair.getKeyId());
        jws.setKey(keyPair.getRsaPrivateKey());
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
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setRequireSubject()
                .setVerificationKey(publicKey)
                .build();
        
        return consumer.processToClaims(jwt);
    }
}
