
package com.example.demo.wsdl_client;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;


/**
 * <p>Classe Java pour sodRequest complex type.
 * 
 * <p>Le fragment de sch�ma suivant indique le contenu attendu figurant dans cette classe.
 * 
 * <pre>
 * &lt;complexType name="sodRequest"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="dataGroup" type="{http://clientws.signserver.org/}dataGroup" maxOccurs="unbounded"/&gt;
 *         &lt;element name="ldsVersion" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="unicodeVersion" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "sodRequest", propOrder = {
    "dataGroup",
    "ldsVersion",
    "unicodeVersion"
})
public class SodRequest {

    @XmlElement(required = true)
    protected List<DataGroup> dataGroup;
    protected String ldsVersion;
    protected String unicodeVersion;

    /**
     * Gets the value of the dataGroup property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the dataGroup property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getDataGroup().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link DataGroup }
     * 
     * 
     */
    public List<DataGroup> getDataGroup() {
        if (dataGroup == null) {
            dataGroup = new ArrayList<DataGroup>();
        }
        return this.dataGroup;
    }

    /**
     * Obtient la valeur de la propri�t� ldsVersion.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getLdsVersion() {
        return ldsVersion;
    }

    /**
     * D�finit la valeur de la propri�t� ldsVersion.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setLdsVersion(String value) {
        this.ldsVersion = value;
    }

    /**
     * Obtient la valeur de la propri�t� unicodeVersion.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getUnicodeVersion() {
        return unicodeVersion;
    }

    /**
     * D�finit la valeur de la propri�t� unicodeVersion.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setUnicodeVersion(String value) {
        this.unicodeVersion = value;
    }

}
