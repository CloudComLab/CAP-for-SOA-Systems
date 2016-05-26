package client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.net.Socket;
import java.security.KeyPair;
import java.security.SignatureException;
import message.Operation;
import service.Config;

/**
 *
 * @author Scott
 */
public class YourClient extends Client {

    public YourClient(KeyPair keyPair, KeyPair spKeyPair) {
        super(Config.SERVICE_HOSTNAME,
              Config.YOUR_SERVICE_PORT,
              keyPair,
              spKeyPair,
              false); // do you support concurrent executing?
    }

    @Override
    protected void handle(Operation op, Socket socket, DataOutputStream out, DataInputStream in)
            throws SignatureException, IllegalAccessException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String getHandlerAttestationPath() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean audit(File spFile) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
