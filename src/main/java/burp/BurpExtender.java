package burp;

import com.codemagi.burp.BaseExtender;
import com.monikamorrow.burp.BurpSuiteTab;
import java.net.MalformedURLException;
import java.net.URL;

public class BurpExtender extends BaseExtender implements IExtensionStateListener {

    protected BurpSuiteTab mTab;
    protected VulnReportLoginComponent comp;
    protected VulnReportOptionsComponent options;
    
    @Override
    protected void initialize() {
        //set the extension Name
	extensionName = "Vulnreport";
        
        //setup the UI tab
        mTab = new BurpSuiteTab("Vulnreport", callbacks);
        comp = new VulnReportLoginComponent();
        mTab.addComponent(comp);
        options = new VulnReportOptionsComponent();
        options.setVisible(false);
        mTab.add(options);        
        
        //listen for load/unload
        callbacks.registerExtensionStateListener(this);
        
        //setup context menus
        callbacks.registerContextMenuFactory(new CustomMenuItem());
        callbacks.registerContextMenuFactory(new DSXSMenuItem());
        callbacks.registerContextMenuFactory(new ScannerMenuItem());
        callbacks.issueAlert("Successfully Initialized VulnReport Plugin");
        
    }
    
    @Override
    public void extensionUnloaded() {
        callbacks.printOutput("Unloading...");
        comp.saveSettings();
    }

    protected URL getVulnReportURL() {
        return comp.getVulnReportBaseURL();
    }
    
    protected URL getVulnReportURL(String path) {
        try {
            return new URL(comp.getVulnReportBaseURL(), path);
        } catch (MalformedURLException ex) {
            printStackTrace(ex);
        }
        return comp.getVulnReportBaseURL();
    }
    
    protected ICookie getSessionCookie() {
        return comp.getSessionCookie();
    }

    protected String getCsrfToken() {
        return comp.getCsrfToken();
    }
    
    protected void updateOptions() {
        callbacks.printOutput("updateOptions");
        options.setVisible(true);
        options.loadReports();
    }
    
    protected Integer getSelectedTestId() {
        return options.getSelectedTestId();
    }

    protected void highlightTab() {
        mTab.highlight();
    }       

}
