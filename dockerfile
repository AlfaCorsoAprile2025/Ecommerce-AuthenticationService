FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
# Prende il file specifico e lo rinomina in 'app.jar' internamente
COPY target/auth-service-1.2.0.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]