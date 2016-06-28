package message;

// copy from http://www.java2s.com/Code/Java/JDK-6/SignSOAPmessage.htm

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.Name;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFactory;
import javax.xml.soap.SOAPPart;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import service.Key;
import service.KeyManager;


/**
 *
 * @author Scott
 */
public class SOAPMessage extends CAPMessage {
    public static MessageFactory MESSAGE_FACTORY;
    private static Logger LOGGER;
    
    static {
        LOGGER = Logger.getLogger(SOAPMessage.class.getName());
        
        try {
            MESSAGE_FACTORY = MessageFactory.newInstance();
        } catch (SOAPException ex) {
            LOGGER.log(Level.SEVERE, null, ex);
        }
    }
    
    private javax.xml.soap.SOAPFactory factory;
    private javax.xml.soap.SOAPMessage message;
    private javax.xml.soap.SOAPHeader header;
    protected javax.xml.soap.SOAPBody body;
    protected Node root;
    
    public SOAPMessage(MessageType type) {
        super(type);
        
        try {
            message = MessageFactory.newInstance().createMessage();
            factory = SOAPFactory.newInstance();
            
            SOAPPart soapPart = message.getSOAPPart();
            SOAPEnvelope soapEnvelope = soapPart.getEnvelope();

            header = soapEnvelope.getHeader();
            Name headerName = soapEnvelope.createName("Signature", "SOAP-SEC", "http://schemas.xmlsoap.org/soap/security/2000-12");
            header.addHeaderElement(headerName);

            body = soapEnvelope.getBody();
            Name bodyName = soapEnvelope.createName("id", "SOAP-SEC", "http://schemas.xmlsoap.org/soap/security/2000-12");
            body.addAttribute(bodyName, "Body");
            
            body.addChildElement(factory.createElement(type.name()));
            
            initContents();
            
            Source source = message.getSOAPPart().getContent();
            
            if (source instanceof DOMSource) {
                root = ((DOMSource) source).getNode();
            } else if (source instanceof SAXSource) {
                InputSource inSource = ((SAXSource) source).getInputSource();
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setNamespaceAware(true);
                DocumentBuilder db = dbf.newDocumentBuilder();

                root = (Node) db.parse(inSource).getDocumentElement();
            }
        } catch (SOAPException | ParserConfigurationException | SAXException | IOException ex) {
            LOGGER.log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Parse the SOAP string into a SOAP document and validate its
     * signature by the public key. If the public key is not given, the
     * verification will be skipped.
     * 
     * @throws SignatureException if the signature is invalid.
     */
    public SOAPMessage(String soapStr, RSAPublicKey publicKey)
            throws SignatureException {
        super(soapStr, publicKey);
        
        try {
            message = SOAPMessage.parseSOAP(soapStr);
            factory = SOAPFactory.newInstance();
            
            SOAPPart soapPart = message.getSOAPPart();
            SOAPEnvelope soapEnvelope = soapPart.getEnvelope();

            header = soapEnvelope.getHeader();
            body = soapEnvelope.getBody();
            
            initContents();
            
            Source source = message.getSOAPPart().getContent();
            
            if (source instanceof DOMSource) {
                root = ((DOMSource) source).getNode();
            } else if (source instanceof SAXSource) {
                InputSource inSource = ((SAXSource) source).getInputSource();
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setNamespaceAware(true);
                DocumentBuilder db = dbf.newDocumentBuilder();

                root = (Node) db.parse(inSource).getDocumentElement();
            }
            
            if (publicKey != null && !validate(publicKey)) {
                throw new SignatureException("Invalid signature.");
            }
        } catch (SOAPException | ParserConfigurationException | SAXException | IOException e) {
            LOGGER.log(Level.SEVERE, null, e);
        }
    }
    
    @Override
    protected void initContents() {
        NodeList bodyNodes = getBody();
        for (int i = 0; i < bodyNodes.getLength(); i++) {
            Node node = bodyNodes.item(i);
            String nodeName = node.getNodeName();
            
            if (nodeName.contains("__")) {
                String prefix = nodeName.substring(0, nodeName.indexOf("__"));
                nodeName = nodeName.substring(nodeName.indexOf("__") + 2);
                
                Map<String, String> subContents = (Map<String, String>) bodyContents.get(prefix);
                
                if (subContents == null) {
                    subContents = new HashMap<>();
                }
                
                subContents.put(nodeName, node.getTextContent());
                bodyContents.put(prefix, subContents);
            } else {
                bodyContents.put(node.getNodeName(), node.getTextContent());
            }
        }
    }
    
    @Override
    public void add2Body(String name, Map<String, String> contents) {
        for (Entry<String, String> entry: contents.entrySet()) {
            add2Body(name + "__" + entry.getKey(), entry.getValue());
        }
    }
    
    @Override
    public void add2Body(String name, String value) {
        try {
            SOAPElement soapElement = factory.createElement(name);
            soapElement.setTextContent(value);
            
            add2Body(soapElement);
        } catch (SOAPException ex) {
            LOGGER.log(Level.SEVERE, null, ex);
        }
    }
    
    public void add2Body(SOAPElement element) {
        try {
            ((SOAPElement) body.getFirstChild()).addChildElement(element);
            
            message.saveChanges();
        } catch (SOAPException ex) {
            LOGGER.log(Level.SEVERE, null, ex);
        }
    }
    
    public NodeList getBody() {
        return body.getFirstChild().getChildNodes();
    }
    
    @Override
    public void sign(KeyPair keyPair, Map<String, String> options) {
        try {
            XMLSignatureFactory sigFactory = XMLSignatureFactory.getInstance();
            Reference ref = sigFactory.newReference("#Body", sigFactory.newDigestMethod(DigestMethod.SHA1, null));
            SignedInfo signedInfo = sigFactory.newSignedInfo(
                sigFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                                                     (C14NMethodParameterSpec) null),
                sigFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                Collections.singletonList(ref));
            KeyInfoFactory kif = sigFactory.getKeyInfoFactory();
            KeyValue kv = kif.newKeyValue(keyPair.getPublic());
            KeyInfo keyInfo = kif.newKeyInfo(Collections.singletonList(kv));
            
            XMLSignature sig = sigFactory.newXMLSignature(signedInfo, keyInfo);
            
            PrivateKey privateKey = keyPair.getPrivate();
            Element envelope = getFirstChildElement(root);
            Element header = getFirstChildElement(envelope);
            DOMSignContext sigContext = new DOMSignContext(privateKey, header);
            sigContext.putNamespacePrefix(XMLSignature.XMLNS, "ds");
            sigContext.setIdAttributeNS(
                getNextSiblingElement(header),
                "http://schemas.xmlsoap.org/soap/security/2000-12", "id");
            
            sig.sign(sigContext);
        } catch (KeyException | NoSuchAlgorithmException | MarshalException |
                 InvalidAlgorithmParameterException | XMLSignatureException e) {
            LOGGER.log(Level.SEVERE, null, e);
        }
    }
    
    private boolean validate(PublicKey publicKey) {
        try {
            Node envelope = root.getFirstChild();
            Node header = envelope.getFirstChild();
            Node signatureNode = header.getChildNodes().item(1);
            
            // Create a DOM XMLSignatureFactory that will be used to unmarshal the
            // document containing the XMLSignature
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
            
            // Create a DOMValidateContext and specify a KeyValue KeySelector
            // and document context
            DOMValidateContext valContext = new DOMValidateContext(publicKey, signatureNode);
            
            // unmarshal the XMLSignature
            XMLSignature signature = fac.unmarshalXMLSignature(valContext);
            
            valContext.setIdAttributeNS(
                getNextSiblingElement(header),
                "http://schemas.xmlsoap.org/soap/security/2000-12",
                "id");
            
            return signature.validate(valContext);
        } catch (MarshalException | XMLSignatureException ex) {
            LOGGER.log(Level.SEVERE, null, ex);
        }

        return false;
    }
    
    @Override
    public String toString() {
        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
//            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
//            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            
            StreamResult result = new StreamResult(new StringWriter());
            DOMSource source = new DOMSource(root);
            transformer.transform(source, result);
            
            return result.getWriter().toString().replaceAll("[\n\r]", "");
        } catch (TransformerException ex) {
            LOGGER.log(Level.SEVERE, null, ex);
        }
        
        return "[toString failed]";
    }
    
    public static javax.xml.soap.SOAPMessage parseSOAP(String string) {
        javax.xml.soap.SOAPMessage message = null;
        
        try {
            byte[] bytes = string.getBytes(StandardCharsets.UTF_8);
            InputStream stream = new ByteArrayInputStream(bytes);
            
            message = MESSAGE_FACTORY.createMessage(null, stream);
        } catch (IOException | SOAPException ex) {
            LOGGER.log(Level.SEVERE, null, ex);
        }
        
        return message;
    }
    
    public static Element getFirstChildElement(Node node) {
        Node child = node.getFirstChild();
        
        while (child != null && child.getNodeType() != Node.ELEMENT_NODE) {
            child = child.getNextSibling();
        }
        
        return (Element) child;
    }
    
    public static Element getNextSiblingElement(Node node) {
        Node sibling = node.getNextSibling();
        
        while (sibling != null && sibling.getNodeType() != Node.ELEMENT_NODE) {
            sibling = sibling.getNextSibling();
        }
        
        return (Element) sibling;
    }
    
    public static void main(String[] args) {
        try {
            KeyPair keyPair = KeyManager.getInstance().getKeyPair(Key.CLIENT);
            Map<String, String> keyInfo = KeyManager.getInstance().getKeyInfo(Key.CLIENT);

            SOAPMessage soap = new SOAPMessage(MessageType.Request);
            
            soap.add2Body("name", "scott");
            soap.add2Body("gender", "male");

            soap.sign(keyPair, keyInfo);

            System.out.println(soap);

            soap = new SOAPMessage(soap.toString(), (RSAPublicKey) keyPair.getPublic());
            
            System.out.println(soap);
        } catch (SignatureException ex) {
            LOGGER.log(Level.SEVERE, null, ex);
        }
    }
}
