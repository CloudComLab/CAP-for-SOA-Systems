package message;

// copy from http://www.java2s.com/Code/Java/JDK-6/SignSOAPmessage.htm

import java.io.IOException;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
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
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stream.StreamResult;
import static org.jcp.xml.dsig.internal.dom.DOMUtils.getFirstChildElement;
import static org.jcp.xml.dsig.internal.dom.DOMUtils.getNextSiblingElement;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;


/**
 *
 * @author Scott
 */
public class SOAPMessage {
    private javax.xml.soap.SOAPFactory factory;
    private javax.xml.soap.SOAPMessage message;
    private javax.xml.soap.SOAPHeader header;
    protected javax.xml.soap.SOAPBody body;
    protected Node root;
    
    public SOAPMessage() {
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
        } catch (SOAPException ex) {
            Logger.getLogger(SOAPMessage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ParserConfigurationException ex) {
            Logger.getLogger(SOAPMessage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SAXException ex) {
            Logger.getLogger(SOAPMessage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(SOAPMessage.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void add2Body(String name, String value) {
        try {
            SOAPElement soapElement = factory.createElement(name);
            soapElement.setTextContent(value);
            
            add2Body(soapElement);
        } catch (SOAPException ex) {
            Logger.getLogger(SOAPMessage.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void add2Body(SOAPElement element) {
        try {
            body.addChildElement(element);
        } catch (SOAPException ex) {
            Logger.getLogger(SOAPMessage.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public NodeList getBody() {
        return body.getChildNodes();
    }
    
    public void sign(KeyPair keyPair) {
        try {
            XMLSignatureFactory sigFactory = XMLSignatureFactory.getInstance();
            Reference ref = sigFactory.newReference("#Body", sigFactory.newDigestMethod(DigestMethod.SHA1, null));
            SignedInfo signedInfo = sigFactory.newSignedInfo(
                sigFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (C14NMethodParameterSpec) null),
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
        } catch (KeyException ex) {
            Logger.getLogger(SOAPMessage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SOAPMessage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(SOAPMessage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (MarshalException ex) {
            Logger.getLogger(SOAPMessage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (XMLSignatureException ex) {
            Logger.getLogger(SOAPMessage.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public boolean validate(PublicKey publicKey) {
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
        } catch (MarshalException ex) {
            Logger.getLogger(SOAPMessage.class.getName()).log(Level.SEVERE, null, ex);
        } catch (XMLSignatureException ex) {
            Logger.getLogger(SOAPMessage.class.getName()).log(Level.SEVERE, null, ex);
        }

        return false;
    }
    
    @Override
    public String toString() {
        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            
            StreamResult result = new StreamResult(new StringWriter());
            DOMSource source = new DOMSource(root);
            transformer.transform(source, result);
            
            return result.getWriter().toString();//.replaceAll("\n", "");
        } catch (TransformerConfigurationException ex) {
            Logger.getLogger(XMLDocument.class.getName()).log(Level.SEVERE, null, ex);
        } catch (TransformerException ex) {
            Logger.getLogger(XMLDocument.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return "[toString failed]";
    }
}
