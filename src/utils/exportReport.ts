import html2canvas from "html2canvas";
import jsPDF from "jspdf";

export async function exportReportAsPDF(reportId: string) {
    const element = document.getElementById(reportId);
    if (!element) return;

    const canvas = await html2canvas(element, { scale: 2 });
    const imgData = canvas.toDataURL("image/png");

    const pdf = new jsPDF("p", "mm", "a4");
    const width = pdf.internal.pageSize.getWidth();
    const height = (canvas.height * width) / canvas.width;

    pdf.addImage(imgData, "PNG", 0, 0, width, height);
    pdf.save("ai-guardrails-report.pdf");
}
