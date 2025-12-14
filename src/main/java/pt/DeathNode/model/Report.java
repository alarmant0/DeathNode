package pt.DeathNode.model;

import java.time.Instant;

public class Report {
    private String reportId;
    private String timestamp;
    private String reporterPseudonym;
    private ReportContent content;
    private int version;
    private String status;

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

    public static class ReportContent {
        private String suspect;
        private String description;
        private String location;

        public String getSuspect() { return suspect; }
        public void setSuspect(String suspect) { this.suspect = suspect; }

        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }

        public String getLocation() { return location; }
        public void setLocation(String location) { this.location = location; }
    }

    public static Report createNew(String reporter, String suspect, String description, String location) {
        Report report = new Report();
        report.setReportId(java.util.UUID.randomUUID().toString());
        report.setTimestamp(Instant.now().toString());
        report.setReporterPseudonym(reporter);
        report.setVersion(2);
        report.setStatus("pending_validation");

        ReportContent content = new ReportContent();
        content.setSuspect(suspect);
        content.setDescription(description);
        content.setLocation(location);
        report.setContent(content);

        return report;
    }
}
