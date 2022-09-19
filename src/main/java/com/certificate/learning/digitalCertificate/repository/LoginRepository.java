package com.certificate.learning.digitalCertificate.repository;

import com.certificate.learning.digitalCertificate.bean.Login;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface LoginRepository extends CrudRepository<Login,String> {

    @Query("select p from Login p where p.username like :name")
    public Login getUser(@Param("name") String username);

}
