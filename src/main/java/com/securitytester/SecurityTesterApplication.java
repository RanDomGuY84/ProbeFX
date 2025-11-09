package com.securitytester;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import java.io.IOException;

public class SecurityTesterApplication extends Application {
    /**
     * JavaFX application entry point. Loads the main FXML UI and shows the
     * primary stage. Keep this class minimal — presentation and behavior live
     * in the FXML and controller.
     */
    @Override
    public void start(Stage primaryStage) throws IOException {
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/fxml/main.fxml"));
        Parent root = loader.load();
        
        primaryStage.setTitle("ProbeFX - Security Testing Suite");
        // Set minimum window size to prevent UI elements from being squished
        primaryStage.setMinWidth(1000);
        primaryStage.setMinHeight(700);
        Scene scene = new Scene(root, 1200, 800);
        String cssResource = getClass().getResource("/styles/styles.css").toExternalForm();
        scene.getStylesheets().add(cssResource);
        primaryStage.setScene(scene);
        primaryStage.show();
        
        // Log the CSS resource path for debugging
        System.out.println("Loading CSS from: " + cssResource);
    }

    public static void main(String[] args) {
        launch(args);
    }
}