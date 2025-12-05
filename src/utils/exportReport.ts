import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import type { Report } from "../App";

export function exportReportAsPDF(report: Report) {
    const pdf = new jsPDF("p", "mm", "a4");
    const pageWidth = pdf.internal.pageSize.getWidth();
    const margin = 14;

    const brandBlue = "#3B82F6";
    const purple = "#7C3AED";
    const textDark = "#111827";
    const textGray = "#4B5563";
    const red = "#DC2626";
    const yellow = "#D97706";
    const green = "#059669";

    const severityColors: Record<string, string> = {
        Critical: red,
        High: yellow,
        Medium: yellow,
        Low: green,
        Info: brandBlue,
    };

    let y = margin;

    // Helper to check page break
    const checkPageBreak = (neededSpace: number) => {
        if (y + neededSpace > pdf.internal.pageSize.getHeight() - 20) {
            pdf.addPage();
            y = margin;
        }
    };

    // Title
    pdf.setFont("Helvetica", "bold");
    pdf.setFontSize(20);
    pdf.setTextColor(brandBlue);
    pdf.text("AI Eye Security Scan Report", margin, y);
    y += 10;

    pdf.setFontSize(11);
    pdf.setTextColor(textDark);

    const meta = [
        `Model: ${report.modelId}`,
        `Library: ${report.library}`,
        `License: ${report.license}`,
        `Downloads: ${report.downloads.toLocaleString()}`,
        `Files Scanned: ${report.files.total}`,
        `Risk Score: ${report.scores.overallScore}/10`,
        `Severity: ${report.severity}`,
    ];

    meta.forEach((line) => {
        pdf.text(line, margin, y);
        y += 6;
    });

    y += 6;

    // Security Findings Section
    pdf.setFontSize(14);
    pdf.setTextColor(brandBlue);
    pdf.text("Security Findings", margin, y);
    y += 4;
    pdf.setDrawColor(textGray);
    pdf.line(margin, y, pageWidth - margin, y);
    y += 6;

    if (report.securityIssues.length > 0) {
        const rows = report.securityIssues.map((i) => [
            i.level,
            i.type,
            i.message,
        ]);

        autoTable(pdf, {
            startY: y,
            head: [["Severity", "Type", "Details"]],
            body: rows,
            theme: "grid",
            styles: {
                fontSize: 9,
                textColor: textDark,
            },
            headStyles: {
                fillColor: brandBlue,
                textColor: "#FFFFFF",
                fontStyle: "bold",
            },
            didParseCell: (data) => {
                if (data.section === "body" && data.column.index === 0) {
                    const sev = data.cell.raw as string;
                    data.cell.styles.textColor = severityColors[sev] || textDark;
                    data.cell.styles.fontStyle = "bold";
                }
            },
        });

        y = (pdf as any).lastAutoTable.finalY + 10;
    } else {
        pdf.setFontSize(11);
        pdf.setTextColor(textGray);
        pdf.text("No issues detected by automated scan.", margin, y);
        y += 10;
    }

    // Static Analysis Section
    if (report.staticAnalysis) {
        checkPageBreak(50);

        pdf.setFontSize(14);
        pdf.setTextColor(purple);
        pdf.text("Static Analysis", margin, y);
        y += 4;
        pdf.setDrawColor(textGray);
        pdf.line(margin, y, pageWidth - margin, y);
        y += 8;

        pdf.setFontSize(10);
        pdf.setTextColor(textDark);

        const staticInfo = [
            `Static Risk Score: ${report.staticAnalysis.staticRiskScore}/100 (${report.staticAnalysis.staticRiskLevel.toUpperCase()})`,
            `Base Model: ${report.staticAnalysis.baseModel || 'Unknown'}`,
            `Architecture: ${report.staticAnalysis.architectureType || 'Unknown'}`,
            `Has Demo (Spaces): ${report.staticAnalysis.hasSpaces ? 'Yes' : 'No'}`,
        ];

        staticInfo.forEach((line) => {
            pdf.text(line, margin, y);
            y += 5;
        });

        if (report.staticAnalysis.unsafeKeywords.length > 0) {
            y += 3;
            pdf.setTextColor(red);
            pdf.text(`Unsafe Patterns Detected: ${report.staticAnalysis.unsafeKeywords.join(', ')}`, margin, y);
            y += 5;
        }

        if (report.staticAnalysis.findings.length > 0) {
            y += 3;
            pdf.setTextColor(textDark);
            pdf.text("Findings:", margin, y);
            y += 5;

            report.staticAnalysis.findings.forEach((finding) => {
                checkPageBreak(10);
                pdf.setFontSize(9);
                pdf.setTextColor(textGray);
                const lines = pdf.splitTextToSize(`• ${finding}`, pageWidth - margin * 2);
                pdf.text(lines, margin + 4, y);
                y += lines.length * 4 + 2;
            });
        }

        y += 5;
    }

    // Red Team Results Section
    if (report.probeResults && report.probeResults.length > 0) {
        checkPageBreak(50);

        pdf.setFontSize(14);
        pdf.setTextColor(red);
        pdf.text("Red Team Testing Results", margin, y);
        y += 4;
        pdf.setDrawColor(textGray);
        pdf.line(margin, y, pageWidth - margin, y);
        y += 6;

        const passCount = report.probeResults.filter(r => r.result === 'pass').length;
        const failCount = report.probeResults.filter(r => r.result === 'fail').length;
        const partialCount = report.probeResults.filter(r => r.result === 'partial').length;

        pdf.setFontSize(10);
        pdf.setTextColor(textDark);
        pdf.text(`Tests Performed: ${report.probeResults.length}`, margin, y);
        y += 5;
        pdf.setTextColor(green);
        pdf.text(`Passed: ${passCount}`, margin, y);
        pdf.setTextColor(red);
        pdf.text(`Failed: ${failCount}`, margin + 40, y);
        pdf.setTextColor(yellow);
        pdf.text(`Partial: ${partialCount}`, margin + 80, y);
        y += 8;

        const probeRows = report.probeResults.map((r) => [
            r.probeId,
            r.category,
            r.result.toUpperCase(),
        ]);

        autoTable(pdf, {
            startY: y,
            head: [["Probe ID", "Category", "Result"]],
            body: probeRows,
            theme: "grid",
            styles: {
                fontSize: 8,
                textColor: textDark,
            },
            headStyles: {
                fillColor: red,
                textColor: "#FFFFFF",
                fontStyle: "bold",
            },
            didParseCell: (data) => {
                if (data.section === "body" && data.column.index === 2) {
                    const result = data.cell.raw as string;
                    if (result === 'PASS') data.cell.styles.textColor = green;
                    else if (result === 'FAIL') data.cell.styles.textColor = red;
                    else if (result === 'PARTIAL') data.cell.styles.textColor = yellow;
                    data.cell.styles.fontStyle = "bold";
                }
            },
        });

        y = (pdf as any).lastAutoTable.finalY + 8;
    }

    // Footer
    const timestamp = new Date().toLocaleString();
    pdf.setFontSize(8);
    pdf.setTextColor(textGray);
    pdf.text(
        `Generated by AI Eye • ${timestamp}`,
        margin,
        pdf.internal.pageSize.getHeight() - 10
    );

    pdf.save(`ai-eye-security-report-${report.modelId.replace('/', '-')}.pdf`);
}

