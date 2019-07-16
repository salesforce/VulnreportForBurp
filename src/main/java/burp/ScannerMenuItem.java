/*
 * Copyright (c) 2019, salesforce.com, inc.
 * All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 * For full license text, see the LICENSE file in the repo root or https://opensource.org/licenses/BSD-3-Clause
 */
package burp;

import burp.impl.HttpService;
import burp.impl.Parameter;
import com.codemagi.burp.HttpRequestThread;
import com.codemagi.burp.TimeLimitedCodeBlock;
import com.codemagi.burp.Utils;
import com.codemagi.burp.parser.HttpRequest;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

class ScannerMenuItem implements IContextMenuFactory {

    private final IExtensionHelpers helpers;
    private final IBurpExtenderCallbacks callbacks;
    private final BurpExtender extender;
    private IContextMenuInvocation invocation;

    public ScannerMenuItem() {
        extender = (BurpExtender) BurpExtender.getInstance();
        callbacks = BurpExtender.getCallbacks();
        helpers = BurpExtender.getHelpers();
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        this.invocation = invocation;

        List<JMenuItem> list = new ArrayList<>();

        //is this a scanner result? 
        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_SCANNER_RESULTS) {
            //get information from the invocation
            IHttpRequestResponse[] ihrrs = invocation.getSelectedMessages();

            JMenuItem item = new JMenuItem("Export to VulnReport");
            item.addActionListener(new ScannerMenuItemListener(ihrrs, invocation.getSelectedIssues()));

            list.add(item);
        }

        return list;
    }

    class ScannerMenuItemListener implements ActionListener {

        private IHttpRequestResponse[] requestResponse;
        private IScanIssue[] issues;

        public ScannerMenuItemListener(IHttpRequestResponse[] ihrrs, IScanIssue[] issues) {
            this.requestResponse = ihrrs;
            this.issues = issues;
        }

        @Override
        public void actionPerformed(ActionEvent ae) {
            for (IScanIssue issue : issues) {
                try {
                    //make sure we have a valid session cookie
                    ICookie cookie = extender.getSessionCookie();
                    if (cookie == null) {
                        JOptionPane.showMessageDialog(null, "Please login to VulnReport.");
                        extender.highlightTab();
                        return;
                    }

                    //export the vuln as an XML file
                    File reportFile = File.createTempFile("xml", "report");
                    IScanIssue[] reportIssue = {issue};
                    callbacks.generateScanReport("XML", reportIssue, reportFile);

                    //execute initial request to create new vuln
                    Integer selectedTestId = extender.getSelectedTestId();
                    if (selectedTestId == null) {
                        //FAIL
                        JOptionPane.showMessageDialog(null, "Please select a test.");
                        extender.highlightTab();
                        return;
                    }
                    URL createUrl = extender.getVulnReportURL("/tests/" + selectedTestId + "/burpxmlup");

                    HttpRequest request = new HttpRequest(createUrl);
                    request.addCookie(extender.getSessionCookie());
                    request.setParameter("_csrf", extender.getCsrfToken());

                    Parameter fileParam = new Parameter("xml", Utils.getFileAsString(reportFile), reportFile.getName(), "text/xml");
                    request.setParameter(fileParam);

                    request.setParameter("uploadxml", "");

                    request.convertToMultipart();
                    request.setContentLength();

                    //issue request, with timeout
                    HttpService service = new HttpService(createUrl);
                    HttpRequestThread requestThread = new HttpRequestThread(service, request.getBytes(), callbacks);
                    try {
                        TimeLimitedCodeBlock.runWithTimeout(requestThread, 60, TimeUnit.SECONDS);
                    } catch (Exception ex) {
                        BurpExtender.printStackTrace(ex);
                    }

                } catch (IOException ex) {
                    BurpExtender.printStackTrace(ex);
                }
            }
        }
    }
}
