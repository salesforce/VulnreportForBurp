package burp;

import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;

class CustomMenuItem implements IContextMenuFactory {

    private final IExtensionHelpers helpers;
    private IContextMenuInvocation invocation;

    public CustomMenuItem() {
        helpers = BurpExtender.getHelpers();
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        this.invocation = invocation;

        //get information from the invocation
        IHttpRequestResponse[] ihrrs = invocation.getSelectedMessages();

        JMenuItem item = new JMenuItem("Copy to Clipboard for VulnReport");
        item.addActionListener(new CustomMenuItemListener(ihrrs));

        List<JMenuItem> list = new ArrayList<>();
        list.add(item);

        return list;
    }

    private java.lang.String vulnReportStart(java.lang.String s) {
        return (new StringBuilder()).append("<~=~=~=~=~=~=~=StartVulnReport:").append(s).append("=~=~=~=~=~=~=~>")
                .toString();
    }

    private java.lang.String vulnReportEnd(java.lang.String s) {
        return (new StringBuilder()).append("<~=~=~=~=~=~=~=EndVulnReport:").append(s).append("=~=~=~=~=~=~=~>")
                .toString();
    }

    private java.lang.String vulnReportWrap(java.lang.String s, java.lang.String s1) {
        return (new StringBuilder()).append(vulnReportStart(s)).append(s1).append(vulnReportEnd(s)).toString();
    }

    private void setClip(java.lang.String s) {
        java.awt.datatransfer.StringSelection stringselection = new StringSelection(s);
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringselection, null);
    }

    class CustomMenuItemListener implements ActionListener {

        private IHttpRequestResponse[] requestResponse;

        //private IHttpRequestResponse[] requestResponse;
        public CustomMenuItemListener(IHttpRequestResponse[] ihrrs) {
            requestResponse = ihrrs;
        }

        @Override
        public void actionPerformed(ActionEvent ae) {
            StringBuilder buf = new StringBuilder();
            for (IHttpRequestResponse requestResponse1 : requestResponse) {
                //append request URL
                IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse1);
                buf.append(vulnReportWrap("URL", requestInfo.getUrl().toString()));
                
                //append request
                byte[] request = requestResponse1.getRequest();
                if (request != null) {
                    buf.append(vulnReportWrap("Request", helpers.base64Encode(request)));
                }
                
                //append response
                byte[] response = requestResponse1.getResponse();
                if (response != null) {
                    buf.append(vulnReportWrap("Response", helpers.base64Encode(response)));
                }
            }

            //set result into clipboard
            setClip(buf.toString());
        }
    }
}
