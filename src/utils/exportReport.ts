import jsPDF from "jspdf";
import { Report } from "../App"; // adjust if your Report interface lives elsewhere

export function exportReportAsPDF(report: Report) {
    const doc = new jsPDF({
        unit: "pt",
        format: "a4"
    });

    let y = 40;

    const addLine = (text: string, size = 12, color = "#000") => {
        doc.setFontSize(size);
        doc.setTextColor(color);
        doc.text(text, 40, y);
        y += size + 6;
    };

    // Header
    doc.setFont("helvetica", "bold");
    addLine("AI Eye • Security Scan Report", 18);

    doc.setFont("helvetica", "normal");
    addLine(`Model: ${report.modelId}`, 12);
    addLine(`Library: ${report.library}`);
    addLine(`License: ${report.license}`);
    addLine(`Downloads: ${report.downloads}`);
    addLine(`Files Scanned: ${report.files.total}`);
    addLine(`Risk Score: ${report.scores.overallScore}/10`);
    addLine(`Severity Level: ${report.severity}`);

    y += 12;
    doc.setFont("helvetica", "bold");
    addLine("Security Findings:", 14, "#004085");

    doc.setFont("helvetica", "normal");
    report.securityIssues.slice(0, 15).forEach((issue) => {
        if (y > 750) {
            doc.addPage();
            y = 40;
        }
        addLine(`[${issue.level}] ${issue.type}`, 12, "#b71c1c");
        addLine(issue.message, 10);
        y += 4;
    });

    y += 12;
    doc.setFont("helvetica", "bold");
    addLine("Red Team Insights:", 14, "#6f42c1");

    doc.setFont("helvetica", "normal");
    addLine(`Risk Score: ${report.redTeamInsights?.score ?? 0}/100`, 12);
    (report.redTeamInsights?.findings || []).slice(0, 6).forEach(f => addLine(`• ${f}`, 10));

    // Footer
    doc.setFontSize(9);
    doc.text(
        `Generated on: ${new Date().toLocaleString()}`,
        40,
        820
    );

    doc.save(`${report.modelId}-security-report.pdf`);
}
