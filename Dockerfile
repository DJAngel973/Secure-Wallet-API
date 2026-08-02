# Stage 1: Build — compiles the project and produces the .jar
FROM maven:3.9-eclipse-temurin-17-alpine AS build

WORKDIR /app

# Copy pom.xml first to leverage Docker layer caching.
# If pom.xml hasn't changed, this layer is reused and dependencies
# are not downloaded again.
COPY pom.xml .

# Download all dependencies without compiling.
# This creates a separate cacheable layer independent of source code.
RUN mvn dependency:go-offline -B

COPY src ./src
RUN mvn package -B -DskipTests

# Stage 2: Run — lightweight final image, only JRE + .jar
FROM eclipse-temurin:17-jre-alpine AS run

# Create non-root user for security.
# OWASP A05: never run container processes as root.
RUN addgroup -S wallet && adduser -S wallet -G wallet

WORKDIR /app

# Copy the .jar from the build stage and set owner in one step.
# The *.jar pattern works because there is only one .jar in target/
# (the sources jar is excluded in assembly config).
COPY --from=build --chown=wallet:wallet /app/target/*.jar app.jar

# Switch to non-root user before running the app.
USER wallet

# This does NOT open the port — docker-compose or docker run -p does that.
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
