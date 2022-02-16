FROM openjdk:11
EXPOSE 8080
WORKDIR /app
ADD /target/jwtapp.jar /app/jwtapp.jar
ENTRYPOINT ["java", "-jar", "/app/jwtapp.jar"]