/*
 * Copyright (c) 2019, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see LICENSE.txt file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package burp;

import burp.impl.HttpService;
import com.codemagi.burp.HttpRequestThread;
import com.codemagi.burp.TimeLimitedCodeBlock;
import com.codemagi.burp.parser.HttpRequest;
import com.codemagi.burp.parser.HttpResponse;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import java.io.IOException;
import java.net.URL;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.TimeUnit;
import javax.swing.DefaultComboBoxModel;

/**
 *
 * @author adetlefsen
 */
public class VulnReportOptionsComponent extends javax.swing.JPanel {

    BurpExtender extender;
    IBurpExtenderCallbacks callbacks;
    
    Review selectedReview;
    Test selectedTest;

    /**
     * Creates new form VulnReportOptionsComponent
     */
    public VulnReportOptionsComponent() {
        extender = (BurpExtender) BurpExtender.getInstance();
        callbacks = BurpExtender.getCallbacks();

        initComponents();
    }

    protected void loadReports() {
        callbacks.printOutput("loadReports");
        
        //get the list of reports
        URL url = extender.getVulnReportURL("/prefetchBH");
        HttpRequest request = new HttpRequest(url);

        //add the session cookie
        request.addCookie(extender.getSessionCookie());

        //issue request, with timeout
        HttpService service = new HttpService(url);
        HttpRequestThread requestThread = new HttpRequestThread(service, request.getBytes(), callbacks);
        try {
            TimeLimitedCodeBlock.runWithTimeout(requestThread, 60, TimeUnit.SECONDS);
        } catch (Exception ex) {
            BurpExtender.printStackTrace(ex);
            setStatusMessage("Request timeout");
        }

        try {
            //get response
            HttpResponse response = HttpResponse.parseMessage(requestThread.getResponse());

            //parse JSON response
            Gson gson = new Gson();
            Review[] reports = gson.fromJson(response.getBody(), Review[].class);
            setStatusMessage("Fetched Reports");

            //set reports into drop-down
            reviewSelect.setModel(new DefaultComboBoxModel(reports));
            
        } catch (IOException ex) {
            BurpExtender.printStackTrace(ex);
            setStatusMessage("Invalid response");
        } catch (JsonSyntaxException jse) {
            BurpExtender.printStackTrace(jse);
            setStatusMessage("Invalid response");
        }
    }

    class Review {

        String name;
        Integer id;
        
        @Override
        public String toString() {
            return name;
        }

        private Integer getId() {
            return id;
        }
    }

    protected void loadTests() {
        callbacks.printOutput("loadTests");
        
        //get the list of reports
        URL url = extender.getVulnReportURL("/reviews/" + selectedReview.getId() + "/testsJson");
        HttpRequest request = new HttpRequest(url);

        //add the session cookie
        request.addCookie(extender.getSessionCookie());

        //issue request, with timeout
        HttpService service = new HttpService(url);
        HttpRequestThread requestThread = new HttpRequestThread(service, request.getBytes(), callbacks);
        try {
            TimeLimitedCodeBlock.runWithTimeout(requestThread, 60, TimeUnit.SECONDS);
        } catch (Exception ex) {
            BurpExtender.printStackTrace(ex);
            setStatusMessage("Request timeout");
        }

        try {
            //get response
            HttpResponse response = HttpResponse.parseMessage(requestThread.getResponse());

            //parse JSON response
            Gson gson = new Gson();
            Test[] tests = gson.fromJson(response.getBody(), Test[].class);
            if (tests == null) {
                setStatusMessage("Invalid response");
            } else {
                setStatusMessage("Fetched Tests");
                //set reports into drop-down
                testSelect.setModel(new DefaultComboBoxModel(tests));
            }
            
            
        } catch (IOException ex) {
            BurpExtender.printStackTrace(ex);
            setStatusMessage("Invalid response");
        } catch (JsonSyntaxException jse) {
            BurpExtender.printStackTrace(jse);
            setStatusMessage("Invalid response");
        }
    }

    class Test {

        String name;
        Integer id;
        
        @Override
        public String toString() {
            return name;
        }

        private Integer getId() {
            return id;
        }
    }

    public void setStatusMessage(String message) {
        statusMessage.setText(message);

        //hide the message after a delay
        Timer timer = new Timer();
        timer.schedule(new CloseDialogTask(), 800);
    }

    class CloseDialogTask extends TimerTask {

        @Override
        public void run() {
            statusMessage.setText("");
        }
    }

    //GETTERS AND SETTERS ------------------------------------------------------
    protected Integer getSelectedTestId() {
        selectedTest = (Test)testSelect.getSelectedItem();
        return (selectedTest == null) ? null : selectedTest.getId();
    }
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        reviewSelect = new javax.swing.JComboBox<>();
        jLabel1 = new javax.swing.JLabel();
        statusMessage = new javax.swing.JLabel();
        testSelect = new javax.swing.JComboBox<>();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();

        reviewSelect.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                reviewSelectItemStateChanged(evt);
            }
        });
        reviewSelect.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                reviewSelectActionPerformed(evt);
            }
        });

        jLabel1.setText("Select Review ");

        jLabel2.setText("Select Test");

        jLabel3.setFont(new java.awt.Font("Tahoma", 1, 13)); // NOI18N
        jLabel3.setForeground(new java.awt.Color(239, 137, 0));
        jLabel3.setText("Export Options");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(testSelect, javax.swing.GroupLayout.PREFERRED_SIZE, 254, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(reviewSelect, javax.swing.GroupLayout.PREFERRED_SIZE, 254, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(0, 146, Short.MAX_VALUE))
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(statusMessage, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel1)
                            .addComponent(jLabel2)
                            .addComponent(jLabel3))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel3)
                .addGap(20, 20, 20)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(reviewSelect, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel2)
                .addGap(4, 4, 4)
                .addComponent(testSelect, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(statusMessage, javax.swing.GroupLayout.PREFERRED_SIZE, 17, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(133, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void reviewSelectItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_reviewSelectItemStateChanged
        // Get the selected Review
        selectedReview = (Review) evt.getItem();
        setStatusMessage("You selected report: " + selectedReview.getId());
        
        //get the tests for the review
        loadTests();
    }//GEN-LAST:event_reviewSelectItemStateChanged

    private void reviewSelectActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_reviewSelectActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_reviewSelectActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JComboBox<Review> reviewSelect;
    private javax.swing.JLabel statusMessage;
    private javax.swing.JComboBox<Test> testSelect;
    // End of variables declaration//GEN-END:variables
}
