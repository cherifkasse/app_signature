package com.example.demo.model;

import javax.persistence.*;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.UniqueConstraint;

/**
 * @author Cherif KASSE
 * @project SunuBtrust360_Enrol
 * @created 13/09/2023/09/2023
 */
@Entity
/*@Table(name="signataire",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = "email")
        }
)*/
public class Signataire {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @NotBlank(message = "Le nom complet ne doit pas etre vide!")
    @Min(value = 3,message = "Le nom complet doit au moins contenir 3 caractères!")
    @Max(value = 50,message = "Le nom complet doit au plus contenir 50 caractères!")

    private String nomSignataire;
    private String categorie;
   // private String application_rattachee;
    private String nom_application;
    @NotBlank(message = "Le code pin ne doit pas etre vide!")
    private String code_pin;
    @NotBlank(message = "L'adresse mail ne doit pas etre vide!")
    @Column(unique=true)
    private String email;

    private String dateCreation;
    private String date_expiration;

    private String dateRenouvellement;

    @NotBlank(message = "Veuillez renseigner le nom de l'entreprise!")
    private String nom_entreprise;
    private String cleDeSignature;

    private String signerKey;

    @NotBlank(message = "Veuillez renseigner le cni ou le passport!")
    private String cniPassport;



    public Signataire(){}

    public String getSignerKey() {
        return signerKey;
    }

    public void setSignerKey(String signerKey) {
        this.signerKey = signerKey;
    }

    public String getCleDeSignature() {
        return cleDeSignature;
    }

    public void setCleDeSignature(String cle_de_signature) {
        this.cleDeSignature = cle_de_signature;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getCategorie() {
        return categorie;
    }

    public void setCategorie(String categorie) {
        this.categorie = categorie;
    }

    /*public String getApplication_rattachee() {
        return application_rattachee;
    }*/

   /* public void setApplication_rattachee(String application_rattachee) {
        this.application_rattachee = application_rattachee;
    }*/

    public String getCniPassport() {
        return cniPassport;
    }

    public void setCniPassport(String cniPassport) {
        this.cniPassport = cniPassport;
    }

    public String getNom_application() {
        return nom_application;
    }

    public void setNom_application(String nom_application) {
        this.nom_application = nom_application;
    }

    public String getDateCreation() {
        return dateCreation;
    }

    public void setDateCreation(String dateCreation) {
        this.dateCreation = dateCreation;
    }

    public String getDate_expiration() {
        return date_expiration;
    }

    public void setDate_expiration(String date_expiration) {
        this.date_expiration = date_expiration;
    }

    public String getNomSignataire() {
        return nomSignataire;
    }

    public void setNomSignataire(String prenom_nom) {
        this.nomSignataire = prenom_nom;
    }

    public String getCode_pin() {
        return code_pin;
    }

    public void setCode_pin(String code_pin) {
        this.code_pin = code_pin;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }


    public String getDateRenouvellement() {
        return dateRenouvellement;
    }

    public void setDateRenouvellement(String dateRenouvellement) {
        this.dateRenouvellement = dateRenouvellement;
    }

    public String getNom_entreprise() {
        return nom_entreprise;
    }

    public void setNom_entreprise(String nom_entreprise) {
        this.nom_entreprise = nom_entreprise;
    }

}
