/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.sso.openid.attacker.evaluation.report;

import java.awt.Color;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
import wsattacker.sso.openid.attacker.log.RequestLogEntry;
import wsattacker.sso.openid.attacker.server.IdpType;

/**
 *
 * @author christiankossmann
 */
public class SvgOutput {
    private static SvgOutput INSTANCE;
    
    // some predefined positions
    private final int START_Y = 50;
    private final int CLIENT_X = 30;
    private final int SP_X = 230;
    private final int ATTACKER_IDP_X = 430;
    private final int ANALYER_IDP_X = 630;
    private final int DEFAULT_VERTICAL_SPACING = 25;
    private final int DEFAULT_STROKE_WIDTH = 1;
    private final int DEFAULT_FONT_SIZE = 12;
    private final Color DEFAULT_TEXT_COLOR = new Color(0, 137, 197);
    
    enum Direction {
        LEFT, RIGHT
    }
    
    private SvgOutput() {
        
    }
    
    public static SvgOutput getSvgOutput() {
        if (INSTANCE == null) {
            INSTANCE = new SvgOutput();
        }
        
        return INSTANCE;
    }
    
    public String generateAttackOverviewFromLog(List<RequestLogEntry> logEntries) {
        String svgContent = "";
        int currentY = START_Y;
        
        // Login Request (horizontal arrow from client to SP)
        svgContent += drawHorizontalLineWithArrow(CLIENT_X, SP_X, currentY, Color.BLACK, DEFAULT_STROKE_WIDTH);
        svgContent += drawText((SP_X-CLIENT_X)/2 + CLIENT_X, currentY-5, DEFAULT_FONT_SIZE, DEFAULT_TEXT_COLOR, "Login Request");
        currentY += 25;
        
        for (RequestLogEntry entry: logEntries) {
            int idpX = entry.getIdpType() == IdpType.ATTACKER ? ATTACKER_IDP_X : ANALYER_IDP_X;
            
            switch (entry.getType()) {
                case HTML:
                    // HTML Discovery (horizontal arrow from SP to IdP)
                    svgContent += drawHorizontalLineWithArrow(SP_X, idpX, currentY, Color.BLACK, DEFAULT_STROKE_WIDTH);
                    svgContent += drawText((idpX-SP_X)/2 + SP_X, currentY-5, DEFAULT_FONT_SIZE, DEFAULT_TEXT_COLOR, "HTML Discovery");
                    break;
                case XRDS:
                    // XRDS Discovery (horizontal arrow from SP to IdP)
                    svgContent += drawHorizontalLineWithArrow(SP_X, idpX, currentY, Color.BLACK, DEFAULT_STROKE_WIDTH);
                    svgContent += drawText((idpX-SP_X)/2 + SP_X, currentY-5, DEFAULT_FONT_SIZE, DEFAULT_TEXT_COLOR, "XRDS Discovery");
                    break;
                case ASSOCIATION:
                    // Association (horizontal line from SP to IdP - arrows on both sides)
                    svgContent += drawHorizontalLineWithArrowOnBothSides(SP_X, idpX, currentY, Color.BLACK, DEFAULT_STROKE_WIDTH);
                    svgContent += drawText((idpX-SP_X)/2 + SP_X, currentY-5, DEFAULT_FONT_SIZE, DEFAULT_TEXT_COLOR, "Association");
                    break;
                case TOKEN_ATTACK:
                case TOKEN_VALID:
                    // Authentication Request (horizontal arrow from SP to client, then, to IdP)
                    svgContent += drawHorizontalLineWithArrow(SP_X, CLIENT_X, currentY, Color.BLACK, DEFAULT_STROKE_WIDTH);
                    svgContent += drawText((SP_X-CLIENT_X)/2 + CLIENT_X, currentY-5, DEFAULT_FONT_SIZE, DEFAULT_TEXT_COLOR, "Authentication Request");
                    svgContent += String.format("<path d=\"M %d %d a 8 8 0 1 0 0 %d\" fill=\"transparent\" stroke=\"black\" stroke-width=\"1\" />", CLIENT_X, currentY, (int)(DEFAULT_VERTICAL_SPACING*0.67));
                    currentY += DEFAULT_VERTICAL_SPACING * 0.67;
                    svgContent += drawHorizontalLineWithArrow(CLIENT_X, idpX, currentY, Color.BLACK, DEFAULT_STROKE_WIDTH);
                    
                    currentY += DEFAULT_VERTICAL_SPACING;
                    
                    // Authentication Response (horizontal arrow from IdP to client, then, to SP)
                    svgContent += drawHorizontalLineWithArrow(idpX, CLIENT_X, currentY, Color.BLACK, DEFAULT_STROKE_WIDTH);
                    svgContent += drawText((idpX-CLIENT_X)/2 + CLIENT_X, currentY-5, DEFAULT_FONT_SIZE, DEFAULT_TEXT_COLOR, "Authentication Response");
                    svgContent += String.format("<path d=\"M %d %d a 8 8 0 1 0 0 %d\" fill=\"transparent\" stroke=\"black\" stroke-width=\"1\" />", CLIENT_X, currentY, (int)(DEFAULT_VERTICAL_SPACING*0.67));
                    currentY += DEFAULT_VERTICAL_SPACING * 0.67;
                    svgContent += drawHorizontalLineWithArrow(CLIENT_X, SP_X, currentY, Color.BLACK, DEFAULT_STROKE_WIDTH);
                    break;
                case XXE:
                    // XXE (horizontal arrow from SP to IdP)
                    svgContent += drawHorizontalLineWithArrow(SP_X, idpX, currentY, Color.BLACK, DEFAULT_STROKE_WIDTH);
                    svgContent += drawText((idpX-SP_X)/2 + SP_X, currentY-5, DEFAULT_FONT_SIZE, DEFAULT_TEXT_COLOR, "XXE");
                    break;
                case CHECK_AUTHENTICATION:
                    // Check Authentication (horizontal arrow from SP to IdP)
                    svgContent += drawHorizontalLineWithArrow(SP_X, idpX, currentY, Color.BLACK, DEFAULT_STROKE_WIDTH);
                    svgContent += drawText((idpX-SP_X)/2 + SP_X, currentY-5, DEFAULT_FONT_SIZE, DEFAULT_TEXT_COLOR, "Direct Verification");
                    break;
            }
            
            currentY += 25;
        }
        
        // success? (horizontal arrow from SP to client)
        svgContent += drawHorizontalLineWithArrow(SP_X, CLIENT_X, currentY, Color.BLACK, DEFAULT_STROKE_WIDTH);
        svgContent += drawText((SP_X-CLIENT_X)/2 + CLIENT_X, currentY-5, DEFAULT_FONT_SIZE, DEFAULT_TEXT_COLOR, "success?");
        
        String svgDocument = "";
        
        try {
            // read from file and replace $svgContent           
            InputStream inputStream = SvgOutput.class.getResourceAsStream("/attack.svg");
            File svgTemplateFile = new File("attack.svg");
            FileUtils.copyInputStreamToFile(inputStream, svgTemplateFile);
            svgDocument = FileUtils.readFileToString(svgTemplateFile);
            svgDocument = svgDocument.replace("$verticalLength", String.format("%d", currentY + 20));
            svgDocument = svgDocument.replace("$svgContent", svgContent);
            svgTemplateFile.delete();
        } catch (IOException ex) {
            Logger.getLogger(HtmlOutput.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return svgDocument;
    }
    
    private String drawText(int x, int y, int fontSize, Color color, String text) {
        return String.format("\t<text x=\"%d\" y=\"%d\" font-size=\"%d\" text-anchor=\"middle\" fill=\"%s\">%s</text>\n",
                             x, y, fontSize, colorToHex(color), text);
    }
    
    private String drawLine(int x1, int y1, int x2, int y2, Color color, int strokeWidth) {        
        return String.format("\t<line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\" stroke=\"%s\" fill=\"transparent\" stroke-width=\"%d\" />\n",
                             x1, y1, x2, y2, colorToHex(color), strokeWidth);
    }
    
    private String drawHorizontalLineWithArrow(int x1, int x2, int y, Color color, int StrokeWidth) {
        String resultString = "";
        
        resultString += drawHorizontalLine(x1, x2, y, color, StrokeWidth);
        
        if (x2 > x1) {
            resultString += drawRightArrow(x2, y);
        } else {
            resultString += drawLeftArrow(x2, y);
        }
        
        return resultString;
    }
    
    private String drawHorizontalLineWithArrowOnBothSides(int x1, int x2, int y, Color color, int StrokeWidth) {
        String resultString = "";
        
        resultString += drawHorizontalLine(x1, x2, y, color, StrokeWidth);
        
        if (x2 > x1) {
            resultString += drawRightArrow(x2, y);
            resultString += drawLeftArrow(x1, y);
        } else {
            resultString += drawRightArrow(x1, y);
            resultString += drawLeftArrow(x2, y);
        }
        
        return resultString;
    }
    
    private String drawHorizontalLine(int x1, int x2, int y, Color color, int StrokeWidth) {
        return drawLine(x1, y, x2, y, color, StrokeWidth);
    }
    
    private String drawRightArrow(int x, int y) {
        return drawArrow(x, y, Direction.RIGHT);
    }
    
    private String drawLeftArrow(int x, int y) {
        return drawArrow(x, y, Direction.LEFT);
    }
    
    private String drawArrow(int x, int y, Direction direction) {
        if (direction == Direction.RIGHT) {
            return String.format("<polygon points=\"%d %d, %d %d, %d %d\" />", x, y, x-7, y-4, x-7, y+4);
        } else {
            return String.format("<polygon points=\"%d %d, %d %d, %d %d\" />", x, y, x+7, y-4, x+7, y+4);
        }
    }

    private String colorToHex(Color color) {
        return String.format("#%02x%02x%02x", color.getRed(),
                                              color.getGreen(),
                                              color.getBlue());
    }
}
