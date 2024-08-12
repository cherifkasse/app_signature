
package com.example.demo.wsdl_client;

import javax.xml.bind.annotation.*;
import java.util.ArrayList;
import java.util.List;


/**
 * <p>Classe Java pour dataResponse complex type.
 * 
 * <p>Le fragment de sch�ma suivant indique le contenu attendu figurant dans cette classe.
 * 
 * <pre>
 * &lt;complexType name="dataResponse"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="archiveId" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="data" type="{http://www.w3.org/2001/XMLSchema}base64Binary" minOccurs="0"/&gt;
 *         &lt;element name="metadata" type="{http://clientws.signserver.org/}metadata" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="requestId" type="{http://www.w3.org/2001/XMLSchema}int"/&gt;
 *         &lt;element name="signerCertificate" type="{http://www.w3.org/2001/XMLSchema}base64Binary" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "dataResponse", propOrder = {
    "archiveId",
    "data",
    "metadata",
    "requestId",
    "signerCertificate"
})
@XmlSeeAlso({
    SodResponse.class
})
public class DataResponse {

    protected String archiveId;
    protected byte[] data;
    @XmlElement(nillable = true)
    protected List<Metadata> metadata;
    protected int requestId;
    protected byte[] signerCertificate;

    /**
     * Obtient la valeur de la propri�t� archiveId.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getArchiveId() {
        return archiveId;
    }

    /**
     * D�finit la valeur de la propri�t� archiveId.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setArchiveId(String value) {
        this.archiveId = value;
    }

    /**
     * Obtient la valeur de la propri�t� data.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getData() {
        return data;
    }

    /**
     * D�finit la valeur de la propri�t� data.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setData(byte[] value) {
        this.data = value;
    }

    /**
     * Gets the value of the metadata property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the metadata property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getMetadata().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link Metadata }
     * 
     * 
     */
    public List<Metadata> getMetadata() {
        if (metadata == null) {
            metadata = new ArrayList<Metadata>();
        }
        return this.metadata;
    }

    /**
     * Obtient la valeur de la propri�t� requestId.
     * 
     */
    public int getRequestId() {
        return requestId;
    }

    /**
     * D�finit la valeur de la propri�t� requestId.
     * 
     */
    public void setRequestId(int value) {
        this.requestId = value;
    }

    /**
     * Obtient la valeur de la propri�t� signerCertificate.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getSignerCertificate() {
        return signerCertificate;
    }

    /**
     * D�finit la valeur de la propri�t� signerCertificate.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setSignerCertificate(byte[] value) {
        this.signerCertificate = value;
    }

}
