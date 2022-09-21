package com.certificate.learning.digitalCertificate.repository;

import com.certificate.learning.digitalCertificate.bean.Certificates;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;
import java.util.List;

@Repository
public interface CertificatesRepository extends CrudRepository<Certificates,Integer> {
    @Query("select p from Certificates p where p.aliasname like :alias ")
    public Certificates getcertest(@Param("alias") String aliasname);

    @Transactional
    @Modifying
    @Query("update Certificates p set p.certificatetest =?2 where p.aliasname =?1")
    public void updateByAlias(String alias, String certificatetest);

    @Transactional
    @Modifying
    public void deleteById(Integer id);

    @Query("select p from Certificates p  where p.username like :name")
    public List<Certificates> getCertByUser(@Param("name") String username);



}
