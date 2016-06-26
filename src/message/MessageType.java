package message;

/**
 *
 * @author Scott
 */
public enum MessageType {
    Request("Q"),
    Response("R"),
    ReplyResponse("RR"),
    Acknowledgement("ACK");
    
    private String abbr;
    
    private MessageType(String abbr) {
        this.abbr = abbr;
    }
    
    @Override
    public String toString() {
        return abbr;
    }
}
