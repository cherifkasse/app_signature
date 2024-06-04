package com.example.demo.model;



import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;

/**
 * @author Cherif KASSE
 * @project SunuBtrust360_Enrol
 * @created 13/02/2024/02/2024 - 15:56
 */
@Entity
@Table(name="signer",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = "cni")
        }
)
@Getter
@Setter
public class Signataire_V2 {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @NotBlank(message = "Le champ 'nomSignataire' est obligatoire")
    @Column(name = "nom_signataire")
    private String nomSignataire;

    @NotBlank(message = "Le champ 'cni' est obligatoire")
    private String cni;

    @Column(name = "id_application")
    private Integer idApplication;

    @Column(name = "code_pin")
    private String codePin;

    @Column(name = "signer_key")
    private String signerKey;

    @Column(name = "date_creation")
    private String dateCreation;

    @Column(name = "date_expiration")
    private String dateExpiration;

    @NotBlank(message = "Le champ 'telephone' est obligatoire")
    @Column(nullable = true)
    private String telephone;
    public Signataire_V2() {
    }

}
