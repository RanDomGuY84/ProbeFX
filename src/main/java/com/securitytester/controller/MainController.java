package com.securitytester.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.securitytester.service.CrawlerService;
import com.securitytester.service.ScannerService;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.TextFieldTableCell;
import javafx.stage.FileChooser;
import org.apache.hc.client5.http.classic.methods.*;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.io.entity.EntityUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainController {
    /**
     * Controller for the main FXML UI. Responsible for wiring UI controls
     * and delegating work to services (crawler, scanner, HTTP proxy).
     *
     * <p>Long-running work is executed on a background thread (via
     * {@link java.util.concurrent.ExecutorService}) and UI updates are
     * performed on the JavaFX application thread using {@link Platform#runLater}.</p>
     */
    @FXML private ComboBox<String> methodCombo;
    @FXML private TextField urlField;
    @FXML private TableView<Map.Entry<String, String>> headersTable;
    @FXML private TableColumn<Map.Entry<String, String>, String> headerNameColumn;
    @FXML private TableColumn<Map.Entry<String, String>, String> headerValueColumn;
    @FXML private TextArea requestBody;
    @FXML private Label responseStatus;
    @FXML private TextArea responseBody;
    @FXML private TableView<Map.Entry<String, String>> responseHeadersTable;
    @FXML private TableColumn<Map.Entry<String, String>, String> responseHeaderNameColumn;
    @FXML private TableColumn<Map.Entry<String, String>, String> responseHeaderValueColumn;
    @FXML private ListView<String> scanResults;
    @FXML private TextField crawlerUrl;
    @FXML private Spinner<Integer> depthSpinner;
    @FXML private ProgressBar crawlerProgress;
    @FXML private ListView<String> crawlerResults;
    @FXML private Label statusLabel;

    private final ObjectMapper objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private final ScannerService scannerService = new ScannerService();
    private final CrawlerService crawlerService = new CrawlerService();
    private final ExecutorService executorService = Executors.newCachedThreadPool();
    private final ObservableList<Map.Entry<String, String>> headers = FXCollections.observableArrayList();
    private final ObservableList<Map.Entry<String, String>> responseHeaders = FXCollections.observableArrayList();

    @FXML
    public void initialize() {
        methodCombo.getItems().addAll("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS");
        methodCombo.setValue("GET");

        depthSpinner.setValueFactory(new SpinnerValueFactory.IntegerSpinnerValueFactory(1, 10, 3));

        headerNameColumn.setCellValueFactory(p -> new SimpleStringProperty(p.getValue().getKey()));
        headerValueColumn.setCellValueFactory(p -> new SimpleStringProperty(p.getValue().getValue()));
        
        headerNameColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        headerValueColumn.setCellFactory(TextFieldTableCell.forTableColumn());
        
        headersTable.setItems(headers);
    // Response headers table setup
    responseHeaderNameColumn.setCellValueFactory(p -> new SimpleStringProperty(p.getValue().getKey()));
    responseHeaderValueColumn.setCellValueFactory(p -> new SimpleStringProperty(p.getValue().getValue()));
    responseHeadersTable.setItems(responseHeaders);

        // Add default headers
        headers.add(Map.entry("User-Agent", "SecurityTesterPro/1.0"));
        headers.add(Map.entry("Accept", "*/*"));
    }

    @FXML
    private void sendRequest() {
        String url = urlField.getText().trim();
        if (url.isEmpty()) {
            showError("URL cannot be empty");
            return;
        }

        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "http://" + url;
        }

        final String finalUrl = url;
        setStatus("Sending request...");
        
        executorService.submit(() -> {
            try (CloseableHttpClient client = HttpClients.createDefault()) {
                HttpUriRequestBase request = createRequest(finalUrl);
                
                // Add headers
                headers.forEach(header -> request.addHeader(header.getKey(), header.getValue()));

                // Add body for POST/PUT
                String method = methodCombo.getValue();
                if (("POST".equals(method) || "PUT".equals(method)) && !requestBody.getText().isEmpty()) {
                    if (request instanceof HttpPost) {
                        ((HttpPost) request).setEntity(new StringEntity(requestBody.getText()));
                    } else if (request instanceof HttpPut) {
                        ((HttpPut) request).setEntity(new StringEntity(requestBody.getText()));
                    }
                }

                // Use response-handler API to avoid deprecated execute(...) overload
                class ResponseData {
                    final int code;
                    final String body;
                    final Header[] headers;

                    ResponseData(int code, String body, Header[] headers) {
                        this.code = code;
                        this.body = body;
                        this.headers = headers;
                    }
                }

                ResponseData respData = client.execute(request, response -> {
                    String responseContentLocal = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
                    return new ResponseData(response.getCode(), responseContentLocal, response.getHeaders());
                });

                Platform.runLater(() -> {
                    responseStatus.setText("Status: " + respData.code);
                    responseBody.setText(respData.body);

                    // Perform security scan
                    scanResults.getItems().clear();
                    Map<String, String> responseHeadersMap = new HashMap<>();
                    responseHeaders.clear();
                    for (Header h : respData.headers) {
                        responseHeadersMap.put(h.getName(), h.getValue());
                        responseHeaders.add(Map.entry(h.getName(), h.getValue()));
                    }

                    scannerService.scanForVulnerabilities(finalUrl, responseHeadersMap, requestBody.getText(), respData.body)
                        .forEach(result -> scanResults.getItems().add(result));

                    setStatus("Ready");
                });
            } catch (Exception e) {
                Platform.runLater(() -> {
                    showError("Request failed: " + e.getMessage());
                    setStatus("Error");
                });
            }
        });
    }

    private HttpUriRequestBase createRequest(String url) {
        return switch (methodCombo.getValue()) {
            case "GET" -> new HttpGet(url);
            case "POST" -> new HttpPost(url);
            case "PUT" -> new HttpPut(url);
            case "DELETE" -> new HttpDelete(url);
            case "HEAD" -> new HttpHead(url);
            case "OPTIONS" -> new HttpOptions(url);
            default -> throw new IllegalArgumentException("Unsupported method: " + methodCombo.getValue());
        };
    }

    @FXML
    private void startCrawling() {
        String url = crawlerUrl.getText().trim();
        if (url.isEmpty()) {
            showError("Crawler URL cannot be empty");
            return;
        }

        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "http://" + url;
        }

        final String finalUrl = url;
        setStatus("Crawling...");
        crawlerProgress.setProgress(0);
        crawlerResults.getItems().clear();

        executorService.submit(() -> {
            try {
                var urls = crawlerService.crawl(finalUrl, depthSpinner.getValue());
                Platform.runLater(() -> {
                    crawlerResults.getItems().addAll(urls);
                    crawlerProgress.setProgress(1);
                    setStatus("Ready");
                });
            } catch (Exception e) {
                Platform.runLater(() -> {
                    showError("Crawling failed: " + e.getMessage());
                    setStatus("Error");
                });
            }
        });
    }

    @FXML
    private void addHeader() {
        headers.add(Map.entry("", ""));
    }

    @FXML
    private void removeHeader() {
        int selectedIndex = headersTable.getSelectionModel().getSelectedIndex();
        if (selectedIndex >= 0) {
            headers.remove(selectedIndex);
        }
    }

    @FXML
    private void formatJson() {
        try {
            String text = requestBody.getText();
            if (!text.isEmpty()) {
                JsonNode jsonNode = objectMapper.readTree(text);
                requestBody.setText(objectMapper.writeValueAsString(jsonNode));
            }
        } catch (IOException e) {
            showError("Invalid JSON format");
        }
    }

    @FXML
    private void clearRequestBody() {
        requestBody.clear();
    }

    @FXML
    private void clearHistory() {
        scanResults.getItems().clear();
        crawlerResults.getItems().clear();
    }

    @FXML
    private void saveResults() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save Results");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text Files", "*.txt"));
        File file = fileChooser.showSaveDialog(null);
        
        if (file != null) {
            try {
                StringBuilder content = new StringBuilder();
                content.append("=== Security Test Results ===\n\n");
                content.append("URL: ").append(urlField.getText()).append("\n");
                content.append("Method: ").append(methodCombo.getValue()).append("\n\n");
                content.append("=== Response ===\n").append(responseBody.getText()).append("\n\n");
                content.append("=== Security Findings ===\n");
                scanResults.getItems().forEach(item -> content.append(item).append("\n"));
                
                java.nio.file.Files.writeString(file.toPath(), content.toString());
                setStatus("Results saved");
            } catch (IOException e) {
                showError("Failed to save results: " + e.getMessage());
            }
        }
    }

    @FXML
    private void showSettings() {
        // TODO: Implement settings dialog
    }

    @FXML
    private void showAbout() {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("About Security Tester Pro");
        alert.setHeaderText("Security Tester Pro");
        alert.setContentText("Version 1.0\nA powerful security testing tool with OWASP scanner integration.");
        alert.showAndWait();
    }

    @FXML
    private void exit() {
        Platform.exit();
    }

    private void showError(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private void setStatus(String status) {
        Platform.runLater(() -> statusLabel.setText(status));
    }
}