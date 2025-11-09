module com.securitytester {
    requires transitive javafx.controls;
    requires transitive javafx.fxml;
    requires transitive javafx.web;
    requires transitive javafx.graphics;
    requires transitive javafx.base;
    requires java.sql;
    requires com.fasterxml.jackson.databind;
    requires org.apache.httpcomponents.client5.httpclient5;
    requires org.apache.httpcomponents.core5.httpcore5;
    requires org.jsoup;
    requires org.slf4j;
    requires ch.qos.logback.classic;
    
    opens com.securitytester to javafx.fxml;
    opens com.securitytester.controller to javafx.fxml;
    opens com.securitytester.model to javafx.base;
    
    exports com.securitytester;
    exports com.securitytester.controller;
    exports com.securitytester.model;
    exports com.securitytester.service;
}