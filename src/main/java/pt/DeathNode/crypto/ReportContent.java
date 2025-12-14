package pt.DeathNode.crypto;

import com.google.gson.annotations.SerializedName;

public class ReportContent {

    @SerializedName("suspect")
    private String suspect;

    @SerializedName("description")
    private String description;

    @SerializedName("location")
    private String location;

    public ReportContent() {}

    public ReportContent(String suspect, String description, String location) {
        this.suspect = suspect;
        this.description = description;
        this.location = location;
    }

    public String getSuspect() { return suspect; }
    public void setSuspect(String suspect) { this.suspect = suspect; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getLocation() { return location; }
    public void setLocation(String location) { this.location = location; }
}
