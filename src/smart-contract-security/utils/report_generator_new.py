"""Enhanced report generation for ZauriScore."""
import json
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Union, List, Type, TypeVar

from jinja2 import Environment, FileSystemLoader

from ..config import config
from ..utils.logger import setup_logger

# Type variable for the report data
try:
    from typing import TypedDict
    
    class ReportData(TypedDict):
        """Type definition for report data structure."""
        metadata: Dict[str, Any]
        decision_summary: Dict[str, Any]
        contract_details: Dict[str, Any]
        findings: List[Dict[str, Any]]
        provenance: Dict[str, Any]
        
except ImportError:
    # Fallback for Python < 3.8
    ReportData = Dict[str, Any]  # type: ignore

T = TypeVar('T', bound='BaseReportExporter')

class BaseReportExporter(ABC):
    """Base class for all report exporters."""
    
    def __init__(self):
        """Initialize the exporter with a logger."""
        self.logger = setup_logger(f"exporter.{self.__class__.__name__}")
    
    @abstractmethod
    def export(
        self, 
        data: ReportData, 
        output_path: Optional[Union[str, Path]] = None
    ) -> Union[str, bytes, Path]:
        """Export the report data to the target format.
        
        Args:
            data: Report data to export
            output_path: Optional path to save the report
            
        Returns:
            The exported report in the target format, or the path to the saved file
        """
        pass
    
    @classmethod
    def create(cls: Type[T], format: str) -> T:
        """Create an exporter instance for the specified format.
        
        Args:
            format: Export format (json, markdown, pdf)
            
        Returns:
            An instance of the appropriate exporter
            
        Raises:
            ValueError: If the format is not supported
        """
        if format == 'json':
            return JSONExporter()
        elif format == 'markdown':
            return MarkdownExporter()
        elif format == 'pdf':
            return PDFExporter()
        else:
            raise ValueError(f"Unsupported export format: {format}")


class JSONExporter(BaseReportExporter):
    """Exports reports in JSON format."""
    
    def export(
        self, 
        data: ReportData, 
        output_path: Optional[Union[str, Path]] = None
    ) -> Union[str, Path]:
        """Export report as JSON.
        
        Args:
            data: Report data to export
            output_path: Optional path to save the JSON file
            
        Returns:
            JSON string if output_path is None, otherwise returns output_path
        """
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        
        if output_path:
            output_path = Path(output_path).with_suffix('.json')
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
            return output_path
            
        return json_str


class MarkdownExporter(BaseReportExporter):
    """Exports reports in Markdown format."""
    
    def __init__(self):
        """Initialize the Markdown exporter with Jinja2 environment."""
        super().__init__()
        templates_dir = Path(__file__).parent / 'templates'
        self.env = Environment(loader=FileSystemLoader(templates_dir))
        self.template = self.env.get_template('report.md.j2')
    
    def export(
        self, 
        data: ReportData, 
        output_path: Optional[Union[str, Path]] = None
    ) -> Union[str, Path]:
        """Export report as Markdown.
        
        Args:
            data: Report data to export
            output_path: Optional path to save the Markdown file
            
        Returns:
            Markdown string if output_path is None, otherwise returns output_path
        """
        # Transform data for the template
        report_data = self._transform_data(data)
        markdown = self.template.render(**report_data)
        
        if output_path:
            output_path = Path(output_path).with_suffix('.md')
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(markdown)
            return output_path
            
        return markdown
    
    def _transform_data(self, data: ReportData) -> Dict[str, Any]:
        """Transform report data for the template."""
        return {
            'metadata': {
                'contract_name': data.get('contract_details', {}).get('ContractName', 'Unknown'),
                'contract_address': data.get('metadata', {}).get('contract_address', 'N/A'),
                'analysis_date': data.get('metadata', {}).get('analysis_date', 
                    datetime.utcnow().isoformat()),
                'tool_version': data.get('metadata', {}).get('tool_version', '1.0.0')
            },
            'findings': self._extract_findings(data),
            'provenance': data.get('provenance', {})
        }
    
    def _extract_findings(self, data: ReportData) -> List[Dict[str, Any]]:
        """Extract and format findings from analysis data."""
        findings = []
        
        # Extract from various sources
        if 'security_issues' in data:
            findings.extend(data['security_issues'])
        
        # Add more sources as needed
        return findings


class PDFExporter(MarkdownExporter):
    """Exports reports in PDF format using WeasyPrint."""
    
    def export(
        self, 
        data: ReportData, 
        output_path: Optional[Union[str, Path]] = None
    ) -> Union[bytes, Path]:
        """Export report as PDF.
        
        Args:
            data: Report data to export
            output_path: Path to save the PDF file
            
        Returns:
            PDF bytes if output_path is None, otherwise returns output_path
            
        Raises:
            ImportError: If WeasyPrint is not installed
        """
        try:
            from weasyprint import HTML
            from weasyprint.text.fonts import FontConfiguration
        except ImportError as e:
            raise ImportError(
                "PDF export requires WeasyPrint. Install with: pip install weasyprint"
            ) from e
        
        # First generate markdown
        markdown = super().export(data)
        
        # Convert markdown to HTML
        import markdown2
        html = markdown2.markdown(markdown)
        
        # Generate PDF
        font_config = FontConfiguration()
        html_doc = HTML(string=html)
        
        if output_path:
            output_path = Path(output_path).with_suffix('.pdf')
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            html_doc.write_pdf(
                str(output_path),
                font_config=font_config,
                stylesheets=[
                    # Add any CSS styles here
                ]
            )
            return output_path
        else:
            return html_doc.write_pdf(font_config=font_config)


def generate_report(
    data: ReportData,
    output_path: Optional[Union[str, Path]] = None,
    format: str = 'json'
) -> Union[str, bytes, Path]:
    """Generate a report in the specified format.
    
    Args:
        data: Report data to include
        output_path: Path to save the report (optional)
        format: Output format ('json', 'markdown', or 'pdf')
        
    Returns:
        The generated report in the requested format
    """
    exporter = BaseReportExporter.create(format)
    return exporter.export(data, output_path)
