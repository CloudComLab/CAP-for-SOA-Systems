package message.fourstep.doublechainhash;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPException;
import message.SOAPMessage;
import org.w3c.dom.NodeList;

/**
 *
 * @author Scott
 */
public class Acknowledgement extends SOAPMessage {
    private static final long serialVersionUID = 20141013L;
    private final String result;
    private final ReplyResponse replyResponse;
    
    public Acknowledgement(String result, ReplyResponse rr) {
        super("acknowledgement");
        
        this.result = result;
        this.replyResponse = rr;
        
        add2Body("result", result);
        add2Body("reply-response", replyResponse.toString());
    }
    
    private Acknowledgement(javax.xml.soap.SOAPMessage message) {
        super(message);
        
        NodeList body = getBody();
        
        this.result = body.item(0).getTextContent();
        this.replyResponse = ReplyResponse.parse(body.item(1).getTextContent());
    }
    
    public String getResult() {
        return result;
    }
    
    public ReplyResponse getReplyResponse() {
        return replyResponse;
    }
    
    public static Acknowledgement parse(String receive) {
        return new Acknowledgement(SOAPMessage.parseSOAP(receive));
    }
}
