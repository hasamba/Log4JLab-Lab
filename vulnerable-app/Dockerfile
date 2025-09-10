FROM maven:3.8.1-openjdk-8 AS build

WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN mvn clean package

FROM openjdk:8u181-jdk-alpine

WORKDIR /app

COPY --from=build /app/target/vulnerable-app-1.0.jar app.jar

EXPOSE 8080

CMD ["java", "-jar", "app.jar"]