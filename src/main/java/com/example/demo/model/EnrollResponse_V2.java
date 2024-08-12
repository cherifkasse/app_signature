package com.example.demo.model;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

import java.util.List;

/**
 * @author Cherif KASSE
 * @project SunuBtrust360_Enrol
 * @created 05/01/2024/01/2024 - 15:57
 */

public class EnrollResponse_V2 {
    private String certificate;
    private String serial_number;
    private String response_format;
    private List<String> certificate_chain;
    @ApiModelProperty(notes = "Code pin ", example = "123456")
    private String codePin;
    @ApiModelProperty(notes = "Id signer ", example = "123")
    private Integer id_signer;

    public Integer getId_signer() {
        return id_signer;
    }

    public void setId_signer(Integer id_signer) {
        this.id_signer = id_signer;
    }

    public String getCodePin() {
        return codePin;
    }

    public void setCodePin(String codePin) {
        this.codePin = codePin;
    }

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public String getSerial_number() {
        return serial_number;
    }

    public void setSerial_number(String serial_number) {
        this.serial_number = serial_number;
    }

    public String getResponse_format() {
        return response_format;
    }

    public void setResponse_format(String response_format) {
        this.response_format = response_format;
    }

    public List<String> getCertificate_chain() {
        return certificate_chain;
    }

    public void setCertificate_chain(List<String> certificate_chain) {
        this.certificate_chain = certificate_chain;
    }
}
