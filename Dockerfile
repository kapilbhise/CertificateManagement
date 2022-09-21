#Load JDK 17

FROM openjdk:17

# Adding jar file to docker container
ADD /target/digitalCertificate-0.0.1-SNAPSHOT.war cms-app.war

# Make PORT available
EXPOSE 2000

# Start the docker by running  jar file
ENTRYPOINT ["java", "-jar", "cms-app.war"]