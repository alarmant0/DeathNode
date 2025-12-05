package pt.DeathNode.crypto;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;

/**
 * Represents a DeathNode report - the core document format.
 * This is the plaintext structure before protection.
 */
public class Report {

    @SerializedName("report_id")
    private String reportId;

    @SerializedName("timestamp")
    private String timestamp;

    @SerializedName("reporter_pseudonym")
    private String reporterPseudonym;

    @SerializedName("content")
    private ReportContent content;

    @SerializedName("version")
    private int version;

    @SerializedName("status")
    private String status;

    // Constructors
    public Report() {}

    public Report(String reportId, String timestamp, String reporterPseudonym,
                  ReportContent content, int version, String status) {
        this.reportId = reportId;
        this.timestamp = timestamp;
        this.reporterPseudonym = reporterPseudonym;
        this.content = content;
        this.version = version;
        this.status = status;
    }

    // Getters and Setters
    public String getReportId() { return reportId; }
    public void setReportId(String reportId) { this.reportId = reportId; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public String getReporterPseudonym() { return reporterPseudonym; }
    public void setReporterPseudonym(String reporterPseudonym) { this.reporterPseudonym = reporterPseudonym; }

    public ReportContent getContent() { return content; }
    public void setContent(ReportContent content) { this.content = content; }

    public int getVersion() { return version; }
    public void setVersion(int version) { this.version = version; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    // JSON serialization
    public String toJson() {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        return gson.toJson(this);
    }

    public static Report fromJson(String json) {
        Gson gson = new Gson();
        return gson.fromJson(json, Report.class);
    }

    @Override
    public String toString() {
        return toJson();
    }
}
