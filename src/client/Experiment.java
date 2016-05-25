package client;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import message.Operation;
import message.OperationType;
import utility.Utils;

/**
 *
 * @author Scott
 */
public class Experiment {
    public static void main(String[] args) throws ClassNotFoundException {
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        KeyPair clientKeyPair = service.KeyPair.CLIENT.getKeypair();
        KeyPair spKeyPair = service.KeyPair.SERVICE_PROVIDER.getKeypair();
        
        Utils.cleanAllAttestations();
        
        Map<String, Client> clients = new LinkedHashMap<>();
        
        clients.put("non-CAP", new NonCAPClient(clientKeyPair, spKeyPair));
        clients.put("CSN", new CSNClient(clientKeyPair, spKeyPair));
        clients.put("ChainHash", new ChainHashClient(clientKeyPair, spKeyPair));
        
        int runTimes = 100;
        
        List<Operation> ops = new ArrayList<>();
        
        service.File[] files = new service.File[] { service.File.HUNDRED_KB };
        
        for (service.File file : files) {
            ops.add(new Operation(OperationType.DOWNLOAD, file.getName(), ""));
//            ops.add(new Operation(OperationType.UPLOAD,
//                    file.getName(),
//                    Utils.readDigest(file.getPath())));
        }
        
        for (Map.Entry<String, Client> client : clients.entrySet()) {
            classLoader.loadClass(client.getValue().getClass().getName());
            
            System.out.println("\n" + client.getKey());
            
            client.getValue().run(ops, runTimes);
        }
        
        clients.clear();
        clients.put("Four-Step-C&L", new ChainHashAndLSNClient("id", clientKeyPair, spKeyPair));
        clients.put("Four-Step-DH", new DoubleChainHashClient("id", clientKeyPair, spKeyPair));
        
        ops.clear();
        for (service.File file : files) {
            for (int j = 0; j < 4; j++) {
                String id = "id" + j;

                ops.add(new Operation(OperationType.DOWNLOAD, file.getName(), "", id));
    //            ops.add(new Operation(OperationType.UPLOAD,
    //                    file.getName(),
    //                    Utils.readDigest(file.getPath())),
    //                    id);
            }
        }
        
        for (Map.Entry<String, Client> client : clients.entrySet()) {
            classLoader.loadClass(client.getValue().getClass().getName());
            
            System.out.println("\n" + client.getKey());
            
            client.getValue().run(ops, runTimes);
        }
    }
}
