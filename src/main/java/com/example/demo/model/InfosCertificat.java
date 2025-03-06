package com.example.demo.model;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class InfosCertificat {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String signerKey;

    private String dateCreation;

    private String dateExpiration;


    private String nomWorker;
}
