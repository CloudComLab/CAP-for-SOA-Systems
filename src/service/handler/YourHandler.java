package service.handler;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.SignatureException;

/**
 *
 * @author Scott
 */
public class YourHandler extends ConnectionHandler {

    public YourHandler(Socket socket, KeyPair keyPair) {
        super(socket, keyPair);
    }

    @Override
    protected void handle(DataOutputStream out, DataInputStream in)
            throws SignatureException, IllegalAccessException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
