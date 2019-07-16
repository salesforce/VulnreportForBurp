# VulnreportForBurp
The Vulnreport plugin for Burp. Allows you to right-click any request/response in Burp and copy the data to a string which can be decoded by Vulnreport when pasted into the Burp Data section. The decoded request/response and URL will be added as vuln data sections.

## Building: 
`mvn clean install`

## Installing: 
In Burp Suite: 
- Go to Extender -> Extensions -> Add
- Locate the compiled jar file (e.g. `target/vulnreport-burp-1.0-SNAPSHOT.jar`)
- Click Open -> Next
- You will see the message `Loaded Vulnreport` in the extension Output tab
