package burp;

import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;

class DSXSMenuItem implements IContextMenuFactory {

    private final IExtensionHelpers helpers;

    public DSXSMenuItem() {
        helpers = BurpExtender.getHelpers();
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        //get information from the invocation
        IHttpRequestResponse[] ihrrs = invocation.getSelectedMessages();

        JMenuItem item = new JMenuItem("Copy DSXS / Sqlmap Request");
        item.addActionListener(new DSXSMenuItemListener(ihrrs));

        List<JMenuItem> list = new ArrayList<>();
        list.add(item);

        return list;
    }

    class DSXSMenuItemListener implements ActionListener {

        private IHttpRequestResponse[] requestResponse;

        //private IHttpRequestResponse[] requestResponse;
        public DSXSMenuItemListener(IHttpRequestResponse[] ihrrs) {
            requestResponse = ihrrs;
        }

        @Override
        public void actionPerformed(ActionEvent ae) {
            for (IHttpRequestResponse requestResponse1 : requestResponse) {
                byte[] request = requestResponse1.getRequest();
                if (request != null) {
                    java.lang.String s1 = new String(request);
                    java.lang.String s2 = null;

                    //get request URL
                    IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse1);
                    String s3 = requestInfo.getUrl().toString();

                    java.lang.String s4 = getHeader("Referer", s1);
                    java.lang.String s5 = getHeader("Cookie", s1);
                    java.lang.String s6 = getHeader("User-Agent", s1);
                    java.lang.String as[] = s1.split("\n");
                    if (s1.startsWith("POST")) {
                        s2 = getBody(s1);
                    } else {
                        BurpExtender.getCallbacks().printOutput("Is Other");
                    }
                    StringBuilder buf = new StringBuilder("");
                    buf.append(" -u \"").append(cmdEscape(s3)).append("\"");
                    if (s4 != null) {
                        buf.append(" --referer=\"").append(cmdEscape(s4))
                                .append("\"");
                    }
                    if (s6 != null) {
                        buf.append(" --user-agent=\"").append(cmdEscape(s6)).append("\"");
                    }
                    if (s5 != null) {
                        buf.append(" --cookie=\"").append(cmdEscape(s5)).append("\"");
                    }
                    if (s2 != null) {
                        buf.append(" --data=\"").append(cmdEscape(s2)).append("\"");
                    }
                    setClip(buf.toString());
                } else {
                    javax.swing.JOptionPane.showMessageDialog(null,
                            "Couldn't find request, or there was an error parsing the request");
                }
            }
        }
    }

    private java.lang.String getBody(java.lang.String s) {
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("^.\n(.*)", 106);
        java.util.regex.Matcher matcher = pattern.matcher(s);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private java.lang.String getHeader(java.lang.String s, java.lang.String s1) {
        java.util.regex.Pattern pattern = java.util.regex.Pattern
                .compile((new StringBuilder()).append("^").append(s).append(": (.+?)$").toString(), 106);
        java.util.regex.Matcher matcher = pattern.matcher(s1);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private void setClip(java.lang.String s) {
        java.awt.datatransfer.StringSelection stringselection = new StringSelection(s);
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringselection, null);
    }

    private java.lang.String cmdEscape(java.lang.String s) {
        return s.replace("\"", "\\\"");
    }
}
