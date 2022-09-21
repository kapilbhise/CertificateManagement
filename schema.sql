create schema telstra;
use telstra;
CREATE TABLE `telstra`.`auser` (
`id` INT NOT NULL AUTO_INCREMENT,
`email` VARCHAR(75) NOT NULL UNIQUE,
`password` VARCHAR(255) NULL,
`username` VARCHAR(75) NOT NULL UNIQUE,
  PRIMARY KEY (`id`)
  );

 CREATE TABLE `telstra`.`certificates` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `aliasname` VARCHAR(45) NULL,
  `certificatetest` LONGBLOB NULL,
  `privatekey` LONGBLOB NULL,
  `publickey` LONGBLOB NULL,
  `caflag` VARCHAR(1) NULL,
  `mail` VARCHAR(75) NULL,
  `username` VARCHAR(75) NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `aliasname_UNIQUE` (`aliasname` ASC) VISIBLE);
  
ALTER TABLE `telstra`.`certificates`
ADD CONSTRAINT `username`
  FOREIGN KEY (`username`)
  REFERENCES `telstra`.`auser` (`username`)
  ON DELETE NO ACTION
  ON UPDATE NO ACTION;