# Security Tester Application

A Spring Boot application for security testing, inspired by Burp Suite. This tool is designed for educational and penetration testing purposes, providing:

- **Custom HTTP Requests:** Build and send GET, POST, PUT, DELETE requests with custom headers and bodies.
- **Response Analysis:** View and analyze HTTP responses in detail.
- **OWASP Top 10 Scanning:** Scan for common vulnerabilities including XSS, SQL Injection, and insecure communication.
- **Web Crawler:** Discover website pages with configurable depth and URL filtering.
- **Request History:** Track all previous requests and findings, including response status codes.

> **Note:** Always ensure you have permission to test any target systems. This tool is for educational and testing purposes only.

## Table of Contents

- [Requirements](#requirements)
- [Quickstart](#quickstart)
- [Features](#features)
- [Database](#database)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)

## Requirements

- Java 17 or higher
- Maven 3.6 or higher

## Running the Application

1. Clone the repository
2. Navigate to the project directory
3. Run the application using Maven:
   ```
   mvn spring-boot:run
   ```

Quickstart (build and run JAR)

1. Build the fat JAR with Maven:
   ```powershell
   mvn clean package -DskipTests
   ```
2. Run the generated JAR (Windows PowerShell):
   ```powershell
   java -jar target\security-tester-0.0.1-SNAPSHOT.jar
   ```

The app will start on http://localhost:8080 by default.

## Features

### Custom Request Builder
- Send GET, POST, PUT, DELETE requests
- Add custom headers
- Include request body
- View response details

### Security Scanner
- Basic OWASP Top 10 vulnerability scanning
- XSS detection
- SQL Injection detection
- Insecure communication detection

### Web Crawler
- Crawl websites to discover pages
- Configurable crawl depth
- URL filtering

### History
- View all previous requests
- Check security findings
- Track response status codes

## Database

The application uses H2 database to store request history. You can access the H2 console at:
`http://localhost:8080/h2-console`

Default credentials:
- JDBC URL: `jdbc:h2:file:./security-tester-db`
- Username: `sa`
- Password: `password`

## Security Notice

This tool is for educational and testing purposes only. Always ensure you have permission to test any target systems.

## Configuration

The most common configuration options are located in `src/main/resources/application.properties`. Example entries you may want to review or override:

```
# Server
server.port=8080

# H2 database (file-based)
spring.datasource.url=jdbc:h2:file:./security-tester-db
spring.datasource.username=sa
spring.datasource.password=password

# Logging
logging.level.root=INFO
```

If you change the JDBC URL or credentials, update the H2 console settings accordingly.

## Contributing

Contributions are welcome. Suggested workflow:

1. Fork the repository on GitHub.
2. Create a feature branch: `git checkout -b feature/your-feature`.
3. Commit changes and push to your fork.
4. Open a pull request describing the change and any testing steps.

Please keep changes focused, include tests where appropriate, and ensure formatting matches the project style.

## License

This project is provided for educational use. Add an appropriate open-source license (e.g. MIT) in a `LICENSE` file if you intend to publish it publicly.