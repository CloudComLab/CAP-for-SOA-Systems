package service;

import java.io.File;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.lang.JoseException;

import utility.Utils;

/**
 * 
 * @author Scott
 */
public class KeyManager {
    private static KeyManager KEY_MANAGER;
    
    private final String KEYS_INFO_FILE_NAME = Config.KEYPAIR_DIR_PATH + "/keys.info";
    
    private final Map<String, KeyPair> keyStore;
    private final Map<String, Map<String, String>> keysInfo;
    
    private KeyManager() {
        keyStore = new HashMap<>();
        keysInfo = new HashMap<>();
        
        File keyPairDir = new File(Config.KEYPAIR_DIR_PATH);
        
        for (File keyPairFile : keyPairDir.listFiles()) {
            String keyId = keyPairFile.getName();
            
            if (!keyId.endsWith("keypair")) {
                continue;
            }
            
            keyId = keyId.substring(0, keyId.indexOf('.'));
            
            KeyPair keyPair = Utils.readKeyPair(GenerateKeyPath(keyId));
            
            keyStore.put(keyId, keyPair);
        }
        
        keysInfo.putAll(Utils.readKeysInfo(KEYS_INFO_FILE_NAME));
        
        for (Key key : Key.values()) {
            if (!keyStore.containsKey(key.getKeyId()) ||
                !keysInfo.containsKey(key.getKeyId())) {
                createKeyPair(key);
            }
        }
    }
    
    public static KeyManager getInstance() {
        if (KEY_MANAGER == null) {
            KEY_MANAGER = new KeyManager();
        }
        
        return KEY_MANAGER;
    }
    
    public KeyPair createKeyPair(Key key) {
        KeyPair keyPair = null;
        
        try {
            RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
            keyPair = new KeyPair(
                    rsaJsonWebKey.getRsaPublicKey(),
                    rsaJsonWebKey.getRsaPrivateKey());
            String path = GenerateKeyPath(key.getKeyId());
            
            Utils.writeKeyPair(path, keyPair);
            keyStore.put(key.getKeyId(), keyPair);
            
            Map<String, String> keyInfo = new HashMap<>();
            keyInfo.put("keyId", rsaJsonWebKey.getKeyId());
            keyInfo.put("keyType", rsaJsonWebKey.getKeyType());
            keyInfo.put("algorithm", AlgorithmIdentifiers.RSA_USING_SHA256);
            keysInfo.put(key.getKeyId(), keyInfo);
            
            Utils.writeKeysInfo(KEYS_INFO_FILE_NAME, keysInfo);
        } catch (JoseException ex) {
            Logger.getLogger(KeyManager.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return keyPair;
    }
    
    public KeyPair getKeyPair(Key key) {
        return keyStore.get(key.getKeyId());
    }
    
    public Map<String, String> getKeyInfo(Key key) {
        return keysInfo.get(key.getKeyId());
    }
    
    public PublicKey getPublicKey(Key key) {
        return getKeyPair(key).getPublic();
    }
    
    public static String GenerateKeyPath(String keyId) {
        return String.format("%s/%s.keypair", Config.KEYPAIR_DIR_PATH, keyId);
    }
}
