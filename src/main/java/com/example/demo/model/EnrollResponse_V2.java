package com.example.demo.model;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

/**
 * @author Cherif KASSE
 * @project SunuBtrust360_Enrol
 * @created 05/01/2024/01/2024 - 15:57
 */

public class EnrollResponse_V2 {
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

}
