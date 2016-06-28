package message;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 *
 * @author Scott
 */
public class Operation {
    private final OperationType type;
    private final String path;
    private final String message;
    private final String clientID;
    private final LinkedHashMap<String, String> map;
    
    public Operation(OperationType type, String path, String msg) {
        this(type, path, msg, "");
    }
    
    public Operation(OperationType type, String path, String msg, String clientID) {
        this.type = type;
        this.path = path.indexOf('\\') != -1 ? path.replace('\\', '/') : path;
        this.message = msg;
        this.clientID = clientID;
        
        map = new LinkedHashMap<>();
        map.put("type", type.toString());
        map.put("path", path);
        map.put("message", msg);
        map.put("clientID", clientID);
    }
    
    public Operation(Map map) {
        this(OperationType.valueOf(String.valueOf(map.get("type"))),
             String.valueOf(map.get("path")),
             String.valueOf(map.get("message")),
             String.valueOf(map.get("clientID")));
    }
    
    public OperationType getType() {
        return type;
    }
    
    public String getPath() {
        return path;
    }
    
    public String getMessage() {
        return message;
    }
    
    public String getClientID() {
        return clientID;
    }
    
    public LinkedHashMap<String, String> toMap() {
        return map;
    }
}
