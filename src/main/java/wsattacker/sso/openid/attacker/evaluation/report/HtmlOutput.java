/*
 * Christian Koßmann (26.09.2014)
 */
package wsattacker.sso.openid.attacker.evaluation.report;

import wsattacker.sso.openid.attacker.evaluation.attack.AttackResult;
import java.awt.Desktop;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import wsattacker.sso.openid.attacker.evaluation.EvaluationResult;
import wsattacker.sso.openid.attacker.evaluation.ServiceProvider;
import wsattacker.sso.openid.attacker.evaluation.training.TrainingResult;
import wsattacker.sso.openid.attacker.log.RequestLogEntry;

/**
 *
 * @author christiankossmann
 */
public class HtmlOutput {
    private static HtmlOutput INSTANCE;
    private final StringBuilder stringBuilder = new StringBuilder();
    private final String filename = System.getProperty("user.dir") + "/report/report.html";
    private int imageNumber = 0;
    private int currentAttackResultNumber = 1;
    
    private HtmlOutput() {
        startHtml();
        /*
        try {
            HtmlOutput.openWebpage(new URI("file://" + filename));
        } catch (URISyntaxException ex) {
            Logger.getLogger(HtmlOutput.class.getName()).log(Level.SEVERE, null, ex);
        }*/
    }
    
    public void startHtml() {
        // clear String Builder
        stringBuilder.setLength(0);
        imageNumber = 0;
        
        // write start of html string
        /*stringBuilder.append("<!DOCTYPE html>\n");
        stringBuilder.append("<html>\n");
        stringBuilder.append("<head>\n");
        stringBuilder.append("\t<title>OpenID Attacker Report</title>\n");
        stringBuilder.append("\t<link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css\">");
        stringBuilder.append("\t<link rel=\"stylesheet\" href=\"screen.css\">");
        stringBuilder.append("\t<meta http-equiv=\"refresh\" content=\"60\" >");
        stringBuilder.append("</head>\n");
        stringBuilder.append("<body>\n");
        stringBuilder.append("\t<div class=\"container\">\n");
        stringBuilder.append("\t\t<div class=\"row\">\n");
        stringBuilder.append("\t\t\t<div class=\"col-md-12\">\n");*/
        
        writeToFile(stringBuilder.toString(), "report/report.html");
    }
    
    public static HtmlOutput getHtmlOutput() {
        if (INSTANCE == null) {
            INSTANCE = new HtmlOutput();
        }
        
        return INSTANCE;
    }
    
    public void addHtml(String line) {
        stringBuilder.append(line).append("\n");
        writeToFile(stringBuilder.toString(), "report/report.html");
    }
    
    /*private void addLinkToImage(File image) {
        // construct file name
        String imageFilename = imageNumber + ".png";
        
        try {
            // copy file in pictures folder
            FileUtils.copyFile(image, new File(System.getProperty("user.dir") + "/report/images/" + imageFilename));
        } catch (IOException ex) {
            Logger.getLogger(ServiceProvider.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        stringBuilder.append("<td><a href='images/").append(imageNumber).append(".png'>Show Screenshot</a></td>\n");
        imageNumber++;
    }*/
    
    public void addUrl(String url) {
        addHtml("<h2>" + url + "<h2>");
    }
    
   /* public static String escapeHTML(String s) {
    StringBuilder out = new StringBuilder(Math.max(16, s.length()));
    for (int i = 0; i < s.length(); i++) {
        char c = s.charAt(i);
        if (c > 127 || c == '"' || c == '<' || c == '>' || c == '&') {
            out.append("&#");
            out.append((int) c);
            out.append(';');
        } else {
            out.append(c);
        }
    }
    return out.toString();
}*/
    
    
    
    private void addLog(List<RequestLogEntry> logEntries, File image) {
        
        addHtml("<td><a href='log_" + imageNumber + ".html'>Show Log</a></td>");

        StringBuilder logStringBuilder = new StringBuilder();
        logStringBuilder.append("<h2>Log</h2>\n");
        
        String svgDocument = SvgOutput.getSvgOutput().generateAttackOverviewFromLog(logEntries);
        File svgFile = new File(System.getProperty("user.dir") + "/report/svg/" + imageNumber + ".svg");
        try {
            FileUtils.writeStringToFile(svgFile, svgDocument);
        } catch (IOException ex) {
            Logger.getLogger(HtmlOutput.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        logStringBuilder.append("<p><a href='svg/" + imageNumber + ".svg'><img src='svg/" + imageNumber + ".svg' class='svg' /></a></p>\n");

        logStringBuilder.append("<ul class=\"nav nav-tabs\">");

        for (int i = 0; i < logEntries.size(); i++) {

            // tab of first entry is active
            if (i == 0) {
                logStringBuilder.append("<li class=\"active\"><a data-toggle=\"tab\" href=\"#section" + i + "\">" + logEntries.get(i).getType() + "</a></li>");
            } else {
                logStringBuilder.append("<li><a data-toggle=\"tab\" href=\"#section" + i + "\">" + logEntries.get(i).getType() + "</a></li>");
            }
        }

        logStringBuilder.append("</ul>");

        /*
         <div class="tab-content">
         <div id="sectionA" class="tab-pane fade in active">
         <h3>Section A</h3>
         <p>Aliquip placeat salvia cillum iphone. Seitan aliquip quis cardigan american apparel, butcher voluptate nisi qui. Raw denim you probably haven't heard of them jean shorts Austin. Nesciunt tofu stumptown aliqua, retro synth master cleanse. Mustache cliche tempor, williamsburg carles vegan helvetica. Reprehenderit butcher retro keffiyeh dreamcatcher synth.</p>
         </div>
         */
        logStringBuilder.append("<div class=\"tab-content\">");

        for (int i = 0; i < logEntries.size(); i++) {
            if (i == 0) {
                logStringBuilder.append("<div id=\"section" + i + "\" class=\"tab-pane fade in active\">");
            } else {
                logStringBuilder.append("<div id=\"section" + i + "\" class=\"tab-pane fade\">");
            }
            logStringBuilder.append("<table class=\"table table-striped log\">\n");
            logStringBuilder.append("<thead>\n");
            logStringBuilder.append("<tr>\n");
            logStringBuilder.append("<th class=\"col-md-6\">Request</th>\n");
            logStringBuilder.append("<th class=\"col-md-6\">Response</th>\n");
            logStringBuilder.append("</tr>\n");
            logStringBuilder.append("</thead>\n");
            logStringBuilder.append("<tr>\n");
            logStringBuilder.append("<td><pre><code>" + logEntries.get(i).getRequest() + "</code></pre></td>");

            logStringBuilder.append("<td><pre><code>" + StringEscapeUtils.escapeHtml4(logEntries.get(i).getResponse()) + "</code></pre></td>");
            logStringBuilder.append("</tr>\n");
            logStringBuilder.append("</table>\n");
            logStringBuilder.append("</div>");
        };

        logStringBuilder.append("</div>");

        logStringBuilder.append("<h2>Screenshot</h2>\n");

        String imageFilename = imageNumber + ".png";

        try {
            // copy file in images folder
            FileUtils.copyFile(image, new File(System.getProperty("user.dir") + "/report/images/" + imageFilename));
        } catch (IOException ex) {
            Logger.getLogger(ServiceProvider.class.getName()).log(Level.SEVERE, null, ex);
        }

        logStringBuilder.append("<p><a href='images/" + imageNumber + ".png'><img src='images/" + imageNumber + ".png' /></a></p>\n");

        writeToFile(logStringBuilder.toString(), "report/log_" + imageNumber + ".html");
        imageNumber++;
    }
    
    public void addTrainingResults(List<TrainingResult> trainingResults) {
        addHtml("<h3>Training</h3>");
        addHtml("<table class=\"table table-striped\">");
        addHtml("<thead>");
        addHtml("<tr>");
        addHtml("<th>#</th>");
        addHtml("<th>Type</th>");
        addHtml("<th>Log</th>");
        addHtml("</tr>");
        addHtml("</thead>");
        
        for (int i = 0; i < trainingResults.size(); i++) {
            TrainingResult result = trainingResults.get(i);
            addHtml("<tr>");
            addHtml("<td>" + (i+1) + "</td>");
            addHtml("<td>" + result.getType() + "</td>");
            addLog(result.getLoginResult().getLogEntries(), result.getLoginResult().getScreenshot());
            //addLinkToImage(result.getLoginResult().getScreenshot());
            addHtml("</tr>");
        }
        
        addHtml("</table>");
    }
    
    private void startAttackResults(String attackName) {
        currentAttackResultNumber = 1;
        
        addHtml("<h3>" + attackName + "</h3>");
        addHtml("<table class=\"table table-striped result\">");
        addHtml("<thead>");
        addHtml("<tr>");
        addHtml("<th class=\"col-md-1\">#</th>");
        addHtml("<th class=\"col-md-7 description\">Description</th>");
        addHtml("<th class=\"col-md-2\">Log</th>");
        addHtml("<th class=\"col-md-2\">Applicable</th>");
        addHtml("</tr>");
        addHtml("</thead>");
    }
    
    private void endAttackResults() {
        addHtml("</table>");
    }
    
    private void addAttackResult(AttackResult attackResult) {
        addHtml("<tr>");
        addHtml("<td>" + currentAttackResultNumber + "</td>");
        addHtml("<td class=\"description\">" + attackResult.getDescription() + "</td>");
        if (attackResult.getLoginResult() != null) {
            addLog(attackResult.getLoginResult().getLogEntries(), attackResult.getLoginResult().getScreenshot());
        } else {
            addHtml("<td>-</td>");
        }
            
        String cssClass;
        switch (attackResult.getInterpretation()) {
            case CRITICAL:
                cssClass = "critical";
                break;
            case RESTRICTED:
                cssClass = "restricted";
                break;
            case PREVENTED:
                cssClass = "prevented";
                break;
            default:
                cssClass = "neutral";
        }
        String text = "";
        switch (attackResult.getResult()) {
            case SUCCESS:
                text = "✔";
                break;
            case FAILURE:
                text = "✗";
                break;
            case NOT_DETECTABLE:
                text = "?";
                break;
            case NOT_PERFORMABLE:
                text = "-";
                break;
        }
        addHtml("<td class=\"" + cssClass + "\">" + text + "</td>");
                        
        addHtml("</tr>");
    }
    
    public void addAttackResults(String attackName, List<AttackResult> attackResults) {
        if (attackResults == null)
            return;
        
        startAttackResults(attackName);
        
        attackResults.forEach((attackResult) -> {
            addAttackResult(attackResult);
            currentAttackResultNumber++;
        });
        
        endAttackResults();
    }
    
    /*public void finishHtml() {
        stringBuilder.append("\t\t\t</div>\n");
        stringBuilder.append("\t\t</div>\n");
        stringBuilder.append("\t</div>\n");
        stringBuilder.append("<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.2.0/js/bootstrap.min.js\"></script>\n");
        stringBuilder.append("</body>\n");
        stringBuilder.append("</html>");
        writeToFile();
    }*/
    
    private void writeToFile(String htmlBody, String filename) {
        try {
            /*
            File htmlTemplateFile = new File("path/template.html");
            String htmlString = FileUtils.readFileToString(htmlTemplateFile);
            String title = "New Page";
            String body = "This is Body";
            htmlString = htmlString.replace("$title", title);
            htmlString = htmlString.replace("$body", body);
            File newHtmlFile = new File("path/new.html");
            FileUtils.writeStringToFile(newHtmlFile, htmlString);
            */
            
            InputStream inputStream = HtmlOutput.class.getResourceAsStream("/template.html");
            File templateFile = new File("template.html");
            FileUtils.copyInputStreamToFile(inputStream, templateFile);
            String htmlString = FileUtils.readFileToString(templateFile);
            htmlString = htmlString.replace("$body", htmlBody);
            File htmlReportFile = new File(filename);
            FileUtils.writeStringToFile(htmlReportFile, htmlString);
            templateFile.delete();
            
            // copy bootstrap.min.css
            inputStream = HtmlOutput.class.getResourceAsStream("/bootstrap.min.css");
            File dest = new File(System.getProperty("user.dir") + "/report/bootstrap.min.css");
            FileUtils.copyInputStreamToFile(inputStream, dest);
            
            // copy screen.css
            inputStream = HtmlOutput.class.getResourceAsStream("/screen.css");
            dest = new File(System.getProperty("user.dir") + "/report/screen.css");
            FileUtils.copyInputStreamToFile(inputStream, dest);
            
            /*try {
                
                
                try (PrintWriter printWriter = new PrintWriter(filename)) {
                    printWriter.print(stringBuilder.toString());
                }
            } catch (FileNotFoundException ex) {
                Logger.getLogger(HtmlOutput.class.getName()).log(Level.SEVERE, null, ex);
            }*/
        } catch (IOException ex) {
            Logger.getLogger(HtmlOutput.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void openReportInDefaultBrowser() {
        try {
            HtmlOutput.openWebpage(new URI("file://" + filename));
        } catch (URISyntaxException ex) {
            Logger.getLogger(HtmlOutput.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /* Open Website in the standard browser of the operating system
     * source: http://stackoverflow.com/questions/10967451/open-a-link-in-browser-with-java-button
    */
    public static void openWebpage(URI uri) {
        Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
        if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
            try {
                desktop.browse(uri);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void openWebpage(URL url) {
        try {
            openWebpage(url.toURI());
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }    

    public void addSummary(EvaluationResult evaluationResult) {
        addHtml("<h3>Summary</h3>");
        addHtml("<table class=\"table table-striped result\">");
        addHtml("<thead>");
        addHtml("<tr>");
        addHtml("<th class=\"col-md-2 \">Total</th>");
        addHtml("<th class=\"col-md-2 \">Critical</th>");
        addHtml("<th class=\"col-md-2 \">Warning</th>");
        addHtml("<th class=\"col-md-2 \">Prevented</th>");
        addHtml("<th class=\"col-md-2 \">Neutral</th>");
        addHtml("<th class=\"col-md-2 \">Duration</th>");
        addHtml("</tr>");
        addHtml("</thead>");
        
        
        int critical = 0;
        int warning = 0;
        int prevented = 0;
        int neutral = 0;
        
        for (Map.Entry<String, List<AttackResult>> attackResults : evaluationResult.getMapOfAttackResult().entrySet())
        {
            if (attackResults.getValue() != null) {
                for (AttackResult attackResult: attackResults.getValue()) {
                    switch (attackResult.getInterpretation()) {
                        case CRITICAL:
                            critical++;
                            break;
                        case RESTRICTED:
                            warning++;
                            break;
                        case PREVENTED:
                            prevented++;
                            break;
                        case NEUTRAL:
                            neutral++;
                            break;
                    }
                }
            }
        }
        
        addHtml("<tr>");
        addHtml("<td>" + (critical+warning+prevented+neutral) + "</td>");
        addHtml("<td class=\"critical\">" + critical + "</td>");
        addHtml("<td class=\"restricted\">" + warning + "</td>");
        addHtml("<td class=\"prevented\">" + prevented + "</td>");
        addHtml("<td class=\"neutral\">" + neutral + "</td>");
        addHtml("<td>" + evaluationResult.getInvestigationTimeFormatted()+ "</td>");
        addHtml("</tr>");
        addHtml("</table>");
    }
}