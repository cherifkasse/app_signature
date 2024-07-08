package com.example.demo.model;

/**
 * @author Cherif KASSE
 * @project SunuBtrust360_Enrol
 * @created 05/03/2024/03/2024 - 11:49
 */


import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import javax.persistence.Entity;

@Entity
@Getter
@Setter
@Table(name="operations_signature")
public class OperationSignature {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @Column(name = "id_signer")
    private Integer idSigner;

    @Column(name = "code_pin")
    private String codePin;

    @Column(name = "signer_key")
    private String signerKey;

    @Column(name = "date_operation")
    private String dateOperation;

    @Column(name = "nom_worker")
    private String nomWorker;


}
