FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S census && adduser -S census -G census
WORKDIR /app
COPY target/census-platform-1.0.0.jar app.jar
RUN chown census:census app.jar
USER census
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD wget -qO- http://localhost:8080/actuator/health || exit 1
ENTRYPOINT ["java", \
    "-XX:+UseContainerSupport", \
    "-XX:MaxRAMPercentage=75.0", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-jar", "app.jar"]
