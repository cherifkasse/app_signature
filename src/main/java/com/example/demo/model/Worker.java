package com.example.demo.model;


import javax.persistence.*;
import javax.persistence.Entity;
/**
 * @author Cherif KASSE
 * @project SunuBtrust360_Enrol
 * @created 08/01/2024/01/2024 - 10:46
 */
@Entity
@Table(name = "worker")
public class Worker {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "id_worker")
    private int idWorker;

    @Column(name = "nom_worker")
    private String nomWorker;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public int getIdWorker() {
        return idWorker;
    }

    public void setIdWorker(int idWorker) {
        this.idWorker = idWorker;
    }

    public String getNomWorker() {
        return nomWorker;
    }

    public void setNomWorker(String nomWorker) {
        this.nomWorker = nomWorker;
    }
}
