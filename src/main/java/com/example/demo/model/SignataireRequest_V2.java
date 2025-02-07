package com.example.demo.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;

/**
 * @author Cherif KASSE
 * @project SunuBtrust360_Enrol
 * @created 13/02/2024/02/2024 - 16:18
 */
@Getter
@Setter
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@ApiModel("Informations du signataire à fournir.")
public class SignataireRequest_V2 {

    @NotBlank(message = "Le champ 'nomSignataire' est obligatoire")
    @ApiModelProperty(notes = "Le nom du signatire.", example = "Cheikh SYLLA")
    private String nomSignataire;

    @NotBlank(message = "Le champ 'cni' est obligatoire")
    @ApiModelProperty(notes = "Le numéro d'identification nationale (NIN) du signataire. ", example = "1 564 1777 00182")
    private String cni;

    @NotBlank(message = "Le champ 'telephone' est obligatoire")
    @ApiModelProperty(notes = "Le numéro de téléphone du signataire.", example = "770000000")
    private String telephone;

    @ApiModelProperty(notes = "L'ID de l'application appelante fourni par GAINDE 2000", example = "35")
    private Integer idApplication;


    public SignataireRequest_V2() {

    }

    public SignataireRequest_V2(String nomSignataire, String cni, String telephone,Integer idApplication) {
        this.nomSignataire = nomSignataire;
        this.cni = cni;
        this.telephone = telephone;
        this.idApplication = idApplication;
    }

    public SignataireRequest_V2(String nomSignataire, String cni) {
        this.nomSignataire = nomSignataire;
        this.cni = cni;

    }

    @Override
    public String toString() {
        return "SignataireRequest_V2{" +
                "nomSignataire='" + nomSignataire + '\'' +
                ", cni='" + cni + '\'' +
                ", telephone='" + telephone + '\'' +
                ", idApplication=" + idApplication +
                '}';
    }

}
