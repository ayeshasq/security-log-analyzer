from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
from typing import List, Dict
import os

class PDFReportGenerator:
    """Generate professional PDF security reports and graphs where necessary"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Create custom styles for the report"""
        
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1976d2'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Subtitle
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#424242'),
            spaceAfter=12,
            fontName='Helvetica-Bold'
        ))
        
        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#d32f2f'),
            spaceAfter=10,
            spaceBefore=15,
            fontName='Helvetica-Bold'
        ))
        
        # Alert box
        self.styles.add(ParagraphStyle(
            name='Alert',
            parent=self.styles['BodyText'],
            fontSize=11,
            textColor=colors.HexColor('#d32f2f'),
            fontName='Helvetica-Bold',
            leftIndent=20,
            rightIndent=20
        ))
    
    def generate_report(self, incidents: List[Dict], executive_summary: str, 
                       timeline_path: str = None, summary_chart_path: str = None) -> str:
        """Generate complete PDF report"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"outputs/security_report_{timestamp}.pdf"
        
        doc = SimpleDocTemplate(
            filename,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        story = []
        
        # Title Page
        story.extend(self._create_title_page(incidents))
        story.append(PageBreak())
        
        # Executive Summary
        story.extend(self._create_executive_summary(executive_summary))
        story.append(PageBreak())
        
        # Statistics Overview
        story.extend(self._create_statistics_page(incidents))
        story.append(Spacer(1, 0.3*inch))
        
        # Add visualizations if available
        if summary_chart_path and os.path.exists(summary_chart_path):
            story.append(Spacer(1, 0.2*inch))
            img = Image(summary_chart_path, width=5*inch, height=4*inch)
            story.append(img)
        
        story.append(PageBreak())
        
        # Detailed Incidents
        story.extend(self._create_detailed_incidents(incidents))
        
        # Timeline
        if timeline_path and os.path.exists(timeline_path):
            story.append(PageBreak())
            story.append(Paragraph("Attack Timeline", self.styles['CustomSubtitle']))
            story.append(Spacer(1, 0.2*inch))
            img = Image(timeline_path, width=6.5*inch, height=3.25*inch)
            story.append(img)
        
        # Build PDF
        doc.build(story)
        
        return filename
    
    def _create_title_page(self, incidents: List[Dict]) -> List:
        """Create report title page"""
        
        elements = []
        
        # Title
        elements.append(Spacer(1, 2*inch))
        title = Paragraph("🛡️ SECURITY INCIDENT REPORT", self.styles['CustomTitle'])
        elements.append(title)
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Subtitle
        subtitle = Paragraph(
            f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}",
            self.styles['Normal']
        )
        elements.append(subtitle)
        
        elements.append(Spacer(1, 0.5*inch))
        
        # Summary box
        high_count = sum(1 for i in incidents if i['severity'] in ['HIGH', 'CRITICAL'])
        
        summary_data = [
            ['Total Incidents', str(len(incidents))],
            ['High/Critical Severity', str(high_count)],
            ['Analysis Date', datetime.now().strftime('%Y-%m-%d')],
            ['Report Type', 'Automated Security Analysis']
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f5f5f5')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        
        elements.append(summary_table)
        
        elements.append(Spacer(1, 1*inch))
        
        # Disclaimer
        disclaimer = Paragraph(
            "<b>CONFIDENTIAL</b><br/>This report contains sensitive security information. "
            "Distribution should be limited to authorized personnel only.",
            self.styles['Normal']
        )
        elements.append(disclaimer)
        
        return elements
    
    def _create_executive_summary(self, summary: str) -> List:
        """Create executive summary page"""
        
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['CustomSubtitle']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Convert summary to paragraphs
        for line in summary.split('\n\n'):
            if line.strip():
                p = Paragraph(line.strip().replace('\n', '<br/>'), self.styles['BodyText'])
                elements.append(p)
                elements.append(Spacer(1, 0.15*inch))
        
        return elements
    
    def _create_statistics_page(self, incidents: List[Dict]) -> List:
        """Create statistics overview"""
        
        elements = []
        
        elements.append(Paragraph("Incident Statistics", self.styles['CustomSubtitle']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Count by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for incident in incidents:
            severity = incident.get('severity', 'LOW')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Count by type
        type_counts = {}
        for incident in incidents:
            itype = incident.get('type', 'UNKNOWN')
            type_counts[itype] = type_counts.get(itype, 0) + 1
        
        # Severity table
        severity_data = [['Severity Level', 'Count']]
        for severity, count in severity_counts.items():
            if count > 0:
                severity_data.append([severity, str(count)])
        
        severity_table = Table(severity_data, colWidths=[3*inch, 2*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1976d2')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')])
        ]))
        
        elements.append(severity_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Type table
        type_data = [['Incident Type', 'Count']]
        for itype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            type_data.append([itype.replace('_', ' ').title(), str(count)])
        
        type_table = Table(type_data, colWidths=[3*inch, 2*inch])
        type_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#d32f2f')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')])
        ]))
        
        elements.append(type_table)
        
        return elements
    
    def _create_detailed_incidents(self, incidents: List[Dict]) -> List:
        """Create detailed incident pages"""
        
        elements = []
        
        elements.append(Paragraph("Detailed Incident Analysis", self.styles['CustomSubtitle']))
        elements.append(Spacer(1, 0.3*inch))
        
        for i, incident in enumerate(incidents, 1):
            # Incident header
            header_text = f"Incident #{i}: {incident['type'].replace('_', ' ').title()}"
            elements.append(Paragraph(header_text, self.styles['SectionHeader']))
            elements.append(Spacer(1, 0.1*inch))
            
            # Incident details table
            details_data = [
                ['Severity', incident.get('severity', 'UNKNOWN')],
                ['Source IP', incident.get('source_ip', 'N/A')],
                ['Event Count', str(incident.get('event_count', 0))],
                ['MITRE ATT&CK', incident.get('mitre', 'N/A')],
            ]
            
            # Add risk score if available
            if 'risk_score' in incident:
                details_data.append(['Risk Score', f"{incident['risk_score']}/100"])
            
            # Add threat intel if available
            if 'threat_intel' in incident:
                ti = incident['threat_intel']
                details_data.append(['Threat Intelligence', 
                                   f"Abuse Score: {ti['abuse_score']}% | Country: {ti['country']}"])
            
            details_table = Table(details_data, colWidths=[2*inch, 4*inch])
            details_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e3f2fd')),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ]))
            
            elements.append(details_table)
            elements.append(Spacer(1, 0.2*inch))
            
            # Description
            desc = Paragraph(f"<b>Description:</b> {incident.get('description', 'N/A')}", 
                           self.styles['BodyText'])
            elements.append(desc)
            elements.append(Spacer(1, 0.15*inch))
            
            # Recommendations
            if 'recommendations' in incident:
                elements.append(Paragraph("<b>Recommended Actions:</b>", self.styles['BodyText']))
                elements.append(Spacer(1, 0.1*inch))
                
                for rec in incident['recommendations'][:5]:  # Limit to 5
                    rec_text = Paragraph(f"• {rec}", self.styles['BodyText'])
                    elements.append(rec_text)
                    elements.append(Spacer(1, 0.05*inch))
            
            elements.append(Spacer(1, 0.3*inch))
            
            # Add page break between incidents (except last one)
            if i < len(incidents):
                elements.append(Spacer(1, 0.2*inch))
        
        return elements
