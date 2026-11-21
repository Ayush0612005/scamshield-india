FROM eclipse-temurin:21-jdk AS build
WORKDIR /src
COPY .mvn .mvn
COPY mvnw pom.xml ./
RUN rm -f .mvn/maven.config && chmod +x mvnw && ./mvnw -B -q dependency:go-offline
COPY src src
RUN ./mvnw -B -q package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /src/target/scamshield-*.jar app.jar
COPY data/advisories data/advisories
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
