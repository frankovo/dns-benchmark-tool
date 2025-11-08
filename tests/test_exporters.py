from dns_benchmark.analysis import BenchmarkAnalyzer
from dns_benchmark.exporters import ExcelExporter, PDFExporter


def test_excel_pdf_export(tmp_path, sample_results):
    analyzer = BenchmarkAnalyzer(sample_results)
    excel_path = tmp_path / "report.xlsx"
    pdf_path = tmp_path / "report.pdf"

    # Excel with all sheets
    ExcelExporter.export_results(
        sample_results,
        analyzer,
        str(excel_path),
        domain_stats=analyzer.get_domain_statistics(),
        record_type_stats=analyzer.get_record_type_statistics(),
        error_stats=analyzer.get_error_statistics(),
    )
    assert excel_path.exists() and excel_path.stat().st_size > 0

    # PDF with success chart
    PDFExporter.export_results(
        sample_results, analyzer, str(pdf_path), include_success_chart=True
    )
    assert pdf_path.exists() and pdf_path.stat().st_size > 0
