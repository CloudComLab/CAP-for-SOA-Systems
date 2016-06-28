package client;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import message.Operation;
import message.OperationType;
import service.Key;
import utility.Utils;

/**
 *
 * @author Scott
 */
public class Experiment {
    public static void main(String[] args) throws ClassNotFoundException {
        ClassLoader classLoader = ClassLoader.getSystemClassLoader();
        
        Utils.cleanAllAttestations();
        
        Map<String, Client> clients = new LinkedHashMap<>();
        
        clients.put("non-CAP", new NonCAPClient(Key.CLIENT, Key.SERVICE_PROVIDER));
        clients.put("Two-Step-SN", new CSNClient(Key.CLIENT, Key.SERVICE_PROVIDER));
        clients.put("Two-Step-CH", new ChainHashClient(Key.CLIENT, Key.SERVICE_PROVIDER));
        
        int runTimes = 1;
        
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
        clients.put("Four-Step-C&L", new ChainHashAndLSNClient("id", Key.CLIENT, Key.SERVICE_PROVIDER));
        clients.put("Four-Step-DH", new DoubleChainHashClient("id", Key.CLIENT, Key.SERVICE_PROVIDER));
        
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
