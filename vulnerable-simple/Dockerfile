FROM openjdk:8u181-jdk-alpine

WORKDIR /app

# Install wget for downloading Log4j
RUN apk add --no-cache wget

# Download vulnerable Log4j 2.14.1 directly
RUN wget https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar && \
    wget https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar

# Copy source files
COPY SimpleVulnerable.java .
COPY log4j2.xml .

# Compile the application
RUN javac -cp "log4j-core-2.14.1.jar:log4j-api-2.14.1.jar:." SimpleVulnerable.java

EXPOSE 8080

# Run with vulnerable settings enabled
CMD ["java", "-cp", ".:log4j-core-2.14.1.jar:log4j-api-2.14.1.jar", \
     "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true", \
     "-Dlog4j2.formatMsgNoLookups=false", \
     "SimpleVulnerable"]