package message;

import java.security.KeyPair;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
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
        
        initContents();
        jws.setPayload(body.toJson());
        
        dirty = false;
    }
    
    @Override
    protected void initContents() {
        for (String claimName: body.getClaimNames()) {
            try {
                if (claimName.contains("__")) {
                    int delimPos = claimName.indexOf("__");
                    String prefix = claimName.substring(0, delimPos);
                    String name = claimName.substring(delimPos + 2);

                    Map<String, String> subContents = (Map<String, String>) bodyContents.get(prefix);

                    if (subContents == null) {
                        subContents = new HashMap<>();
                    }

                    subContents.put(name, body.getStringClaimValue(claimName));
                    bodyContents.put(prefix, subContents);
                } else {
                    bodyContents.put(claimName, body.getStringClaimValue(claimName));
                }
            } catch (MalformedClaimException ex) {
                Logger.getLogger(JsonWebToken.class.getName()).log(Level.SEVERE, null, ex);
            } 
        }
    }
    
    @Override
    public void add2Body(String name, String value) {
        body.setClaim(name, value);
        
        dirty = true;
    }
    
    @Override
    public void add2Body(String name, Map<String, String> content) {
        for (Entry<String, String> entry: content.entrySet()) {
            add2Body(name + "__" + entry.getKey(), entry.getValue());
        }
    }
    
    @Override
    public void sign(KeyPair keyPair, Map<String, String> options) {
        if (options == null) {
            throw new NullPointerException("options cannot be null!");
        }
        
        sign((RSAPrivateKey) keyPair.getPrivate(),
             options.get("keyId"),
             options.get("algorithm"));
    }
    
    /**
     * Sign this JSON web token with the specific key and signing algorithm.
     */
    public void sign(RSAPrivateKey privateKey, String keyId, String algorithm) {
        jws.setKey(privateKey);
        jws.setKeyIdHeaderValue(keyId);
        jws.setAlgorithmHeaderValue(algorithm);
    }
    
    @Override
    public String toString() {
        if (originMessage != null) {
            return originMessage;
        }
        
        try {
            if (dirty) {
                jws.setPayload(body.toJson());
                
                dirty = false;
            }
            
            if (jws.getAlgorithmHeaderValue() == null) {
                jws.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
                jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.NONE);
            }
            
            originMessage = jws.getCompactSerialization();
            
            return originMessage;
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
        } else {
            builder.setDisableRequireSignature();
            builder.setSkipSignatureVerification();
            builder.setJwsAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
        }
        
        return builder.build().processToClaims(jwt);
    }
}
