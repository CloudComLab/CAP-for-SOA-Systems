package service;

/**
 *
 * @author Scott
 */
public interface Config {
    public String SERVICE_HOSTNAME = "localhost";
    public int NONCAP_SERVICE_PORT = 3000;
    public int CSN_SERVICE_PORT = 3001;
    public int CHAINHASH_SERVICE_PORT = 3002;
    public int CHAINHASH_LSN_SERVICE_PORT = 3003;
    public int DOUBLECHAINHASH_SERVICE_PORT = 3004;
    
    public String DEFAULT_CHAINHASH = "default";
    
    public String DATA_DIR_PATH = "data";
    public String ATTESTATION_DIR_PATH = "attestations";
    public String DOWNLOADS_DIR_PATH = "downloads";
    public String KEYPAIR_DIR_PATH = "keypairs";
    
    public String DIGEST_ALGORITHM = "SHA-1";
    
    public int NUM_PROCESSORS = 1; // Runtime.getRuntime().availableProcessors();
}
