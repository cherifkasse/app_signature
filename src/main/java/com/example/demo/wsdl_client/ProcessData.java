
package com.example.demo.wsdl_client;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;


/**
 * <p>Classe Java pour processData complex type.
 * 
 * <p>Le fragment de sch�ma suivant indique le contenu attendu figurant dans cette classe.
 * 
 * <pre>
 * &lt;complexType name="processData"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="worker" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="metadata" type="{http://clientws.signserver.org/}metadata" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="data" type="{http://www.w3.org/2001/XMLSchema}base64Binary" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "processData", propOrder = {
    "worker",
    "metadata",
    "data"
})
public class ProcessData {

    protected String worker;
    protected List<Metadata> metadata;
    @XmlElementRef(name = "data", type = JAXBElement.class, required = false)
    protected JAXBElement<byte[]> data;

    /**
     * Obtient la valeur de la propri�t� worker.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getWorker() {
        return worker;
    }

    /**
     * D�finit la valeur de la propri�t� worker.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setWorker(String value) {
        this.worker = value;
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
     * Obtient la valeur de la propri�t� data.
     * 
     * @return
     *     possible object is
     *     {@link JAXBElement }{@code <}{@link byte[]}{@code >}
     *     
     */
    public JAXBElement<byte[]> getData() {
        return data;
    }

    /**
     * D�finit la valeur de la propri�t� data.
     * 
     * @param value
     *     allowed object is
     *     {@link JAXBElement }{@code <}{@link byte[]}{@code >}
     *     
     */
    public void setData(JAXBElement<byte[]> value) {
        this.data = value;
    }

}
