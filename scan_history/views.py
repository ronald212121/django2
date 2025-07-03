from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q, Sum
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
import matplotlib.pyplot as plt
import os
from django.conf import settings
import base64
from io import BytesIO
import json
import numpy as np
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from datetime import datetime

from core.models import ScanResult

@login_required
def scan_history_view(request):
    # Get scan results only for the logged-in user
    scans = ScanResult.objects.filter(user=request.user)
    
    # Handle search and filtering
    search_query = request.GET.get('search', '')
    tool_filter = request.GET.get('tool', '')
    sort_option = request.GET.get('sort', 'latest')
    
    # Apply search filter
    if search_query:
        scans = scans.filter(
            Q(target__icontains=search_query) | 
            Q(scan_type__icontains=search_query)
        )
    
    # Apply tool filter
    if tool_filter:
        scans = scans.filter(tool=tool_filter)
    
    # Apply sorting
    if sort_option == 'oldest':
        scans = scans.order_by('created_at')
    elif sort_option == 'most_vuln':
        # Sum all vulnerability counts and order by total
        scans = scans.annotate(
            total_vulns=Sum('critical_count') + Sum('high_count') + 
                        Sum('medium_count') + Sum('low_count') + Sum('info_count')
        ).order_by('-total_vulns')
    elif sort_option == 'least_vuln':
        scans = scans.annotate(
            total_vulns=Sum('critical_count') + Sum('high_count') + 
                        Sum('medium_count') + Sum('low_count') + Sum('info_count')
        ).order_by('total_vulns')
    else:  # default to latest
        scans = scans.order_by('-created_at')
    
    # Pagination
    paginator = Paginator(scans, 10)  # Show 10 scans per page
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'history': page_obj
    }
    
    return render(request, 'scan_history/history.html', context)

@login_required
def scan_result_view(request, scan_id):
    # Only allow user to view their own scan results
    scan = get_object_or_404(ScanResult, id=scan_id, user=request.user)
    
    print(f"DEBUG: Loading scan result ID {scan_id}, type: {scan.scan_type}")
    
    # Generate vulnerability chart with improved styling
    plt.style.use('default')  # Use clean default style
    fig, ax = plt.subplots(figsize=(10, 8))
    fig.patch.set_facecolor('white')
    
    # Data for pie chart
    labels = ['Critical', 'High', 'Medium', 'Low', 'Info']
    
    # Mengambil nilai scan counts dan menangani nilai None/NaN
    critical = scan.critical_count if scan.critical_count is not None else 0
    high = scan.high_count if scan.high_count is not None else 0
    medium = scan.medium_count if scan.medium_count is not None else 0
    low = scan.low_count if scan.low_count is not None else 0
    info = scan.info_count if scan.info_count is not None else 0
    
    sizes = [critical, high, medium, low, info]
    
    # Pastikan semua nilai adalah angka, bukan NaN
    sizes = [0 if (x is None or np.isnan(x)) else x for x in sizes]
    
    # Enhanced colors with better contrast
    colors_chart = ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#6c757d']  # Bootstrap colors
    explode = (0.1, 0.05, 0, 0, 0)  # explode critical and high for emphasis
    
    # Periksa apakah semua nilai dalam sizes adalah 0
    total_findings = sum(sizes)  # CHANGED: Total findings, not vulnerabilities
    
    if total_findings == 0:
        # Create a simple "No Vulnerabilities" chart
        ax.pie([1], labels=['No Findings'], colors=['#28a745'], 
               autopct='', startangle=90, textprops={'fontsize': 14, 'fontweight': 'bold'})
        ax.set_title('Vulnerability Distribution', fontsize=16, fontweight='bold', pad=20)
    else:
        # Filter out zero values for cleaner chart
        filtered_sizes = []
        filtered_labels = []
        filtered_colors = []
        filtered_explode = []
        
        for i, size in enumerate(sizes):
            if size > 0:
                filtered_sizes.append(size)
                filtered_labels.append(f'{labels[i]}\n({size})')
                filtered_colors.append(colors_chart[i])
                filtered_explode.append(explode[i])
        
        # Create pie chart with better formatting
        wedges, texts, autotexts = ax.pie(
            filtered_sizes, 
            labels=filtered_labels,
            colors=filtered_colors,
            explode=filtered_explode,
            autopct='%1.1f%%',
            startangle=90,
            textprops={'fontsize': 12, 'fontweight': 'bold'},
            pctdistance=0.85
        )
        
        # Enhance text appearance
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(11)
        
        # Add title
        ax.set_title('Vulnerability Distribution', fontsize=16, fontweight='bold', pad=20)
        
        # Add legend
        ax.legend(wedges, [f'{label}: {size}' for label, size in zip([labels[i] for i in range(len(sizes)) if sizes[i] > 0], filtered_sizes)],
                 title="Findings",
                 loc="center left",
                 bbox_to_anchor=(1, 0, 0.5, 1),
                 fontsize=10)
    
    ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
    
    # Convert plot to base64 for embedding in HTML
    buffer = BytesIO()
    plt.savefig(buffer, format='png', dpi=150, bbox_inches='tight', 
                facecolor='white', edgecolor='none')
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    plt.close(fig)  # Tutup figure untuk menghindari memory leak
    
    chart = base64.b64encode(image_png).decode('utf-8')
    
    # FIXED: PRIORITIZE ENGINE SCORE OVER MODEL SCORE
    score = None
    engine_score = None
    model_score = None
    
    # 1. Try to get engine score first (most accurate)
    try:
        result_data = json.loads(scan.result)
        engine_score = result_data.get('security_score', None)
        if engine_score is not None:
            score = engine_score
            print(f"DEBUG: Using ENGINE score: {score}")
        else:
            print(f"DEBUG: No engine score found in result data")
    except Exception as e:
        print(f"DEBUG: Could not parse engine score: {e}")
    
    # 2. Fallback to model score if engine score not available
    if score is None:
        model_score = scan.get_security_score()
        score = model_score
        print(f"DEBUG: Using MODEL score (fallback): {score}")
    else:
        # Compare with model score for debugging
        model_score = scan.get_security_score()
        if abs(engine_score - model_score) > 5:
            print(f"DEBUG: Score difference detected - Engine: {engine_score}, Model: {model_score}")
            print(f"DEBUG: Using ENGINE score as it's more accurate")
    
    # SPECIAL: For security-aware scans, always prioritize engine score
    if 'security_aware' in scan.scan_type.lower() and engine_score is not None:
        score = engine_score
        print(f"DEBUG: Security-aware scan detected - FORCED ENGINE score: {score}")
    
    # Cap score between 0 and 100
    score = max(0, min(100, int(score)))
    
    # FIXED: Better error handling for result_data
    try:
        result_data = scan.get_result_dict()
        print(f"DEBUG: Successfully parsed result_data for {scan.scan_type}")
    except Exception as e:
        print(f"DEBUG: Error parsing result_data for {scan.scan_type}: {e}")
        # Fallback - parse JSON manually
        try:
            result_data = json.loads(scan.result)
            print(f"DEBUG: Fallback JSON parse successful")
        except Exception as json_error:
            print(f"DEBUG: JSON parse also failed: {json_error}")
            result_data = {
                'error': 'Failed to parse scan results',
                'raw_result_preview': scan.result[:200] if scan.result else 'No result data'
            }
    
    print(f"DEBUG: Final score for scan {scan_id}: {score}")
    print(f"DEBUG: Score source: {'ENGINE' if engine_score is not None else 'MODEL'}")
    print(f"DEBUG: Result data keys: {list(result_data.keys()) if isinstance(result_data, dict) else 'Not a dict'}")
    
    context = {
        'scan': scan,
        'chart': chart,
        'score': int(score),
        'result_data': result_data,
    }
    
    print(f"DEBUG: Context prepared successfully for scan {scan_id}")
    
    return render(request, 'scan_history/result.html', context)

@login_required
def export_recommendation_pdf(request, scan_id):
    """ENHANCED: Export Comprehensive Security Report with Vulnerability Details"""
    scan = get_object_or_404(ScanResult, id=scan_id, user=request.user)
    
    # Create HTTP response with PDF content type
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="Comprehensive_Security_Report_Scan_{scan_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf"'
    
    # Create PDF document
    doc = SimpleDocTemplate(response, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.darkblue,
        spaceAfter=30,
        alignment=1  # Center alignment
    )
    
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.darkblue,
        spaceAfter=20
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=11,
        spaceAfter=12,
        leftIndent=0,
        rightIndent=0
    )
    
    # Title
    story.append(Paragraph("Comprehensive Security Assessment Report", title_style))
    story.append(Spacer(1, 20))
    
    # ENHANCED: Executive Summary Table
    executive_data = [
        ['Executive Summary', ''],
        ['Target:', scan.target],
        ['Tool:', scan.tool.upper()],
        ['Scan Type:', scan.scan_type.title()],
        ['Date:', scan.created_at.strftime("%d %B %Y, %H:%M:%S")],
        ['Security Score:', f"{scan.get_security_score()}/100"],
        ['Risk Level:', scan.get_risk_level()],
        ['Total Vulnerabilities:', str(scan.get_total_vulnerabilities())],
        ['Total Findings:', str(scan.get_total_findings())]
    ]
    
    executive_table = Table(executive_data, colWidths=[2*inch, 4*inch])
    executive_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(executive_table)
    story.append(Spacer(1, 30))
    
    # ENHANCED: Vulnerability Summary Table
    if scan.get_total_vulnerabilities() > 0:
        vuln_data = [
            ['Vulnerability Summary by Severity', 'Count', 'Risk Level'],
            ['🚨 Critical', str(scan.critical_count), 'VERY HIGH'],
            ['🔴 High', str(scan.high_count), 'HIGH'],
            ['🟡 Medium', str(scan.medium_count), 'MODERATE'],
            ['🟢 Low', str(scan.low_count), 'LOW'],
            ['ℹ️ Info', str(scan.info_count), 'INFORMATIONAL']
        ]
        
        vuln_table = Table(vuln_data, colWidths=[3*inch, 1*inch, 1.5*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(vuln_table)
        story.append(Spacer(1, 30))
    
    # NEW: DETAILED VULNERABILITY TABLE
    try:
        result_data = json.loads(scan.result)
        all_vulnerabilities = []
        
        # Collect all vulnerabilities
        if 'vulnerabilities' in result_data and result_data['vulnerabilities']:
            all_vulnerabilities.extend(result_data['vulnerabilities'])
        
        if all_vulnerabilities and scan.get_total_vulnerabilities() > 0:
            story.append(Paragraph("🔍 Detailed Vulnerability Analysis", subtitle_style))
            story.append(Spacer(1, 10))
            
            # Filter actual vulnerabilities (not positive features)
            actual_vulnerabilities = []
            positive_features = []
            info_findings = []
            
            for vuln in all_vulnerabilities:
                is_positive = vuln.get('is_positive', False)
                severity = vuln.get('severity', 'info').lower()
                
                if is_positive:
                    positive_features.append(vuln)
                elif severity == 'info' and vuln.get('type') == 'Infrastructure Finding':
                    info_findings.append(vuln)
                else:
                    actual_vulnerabilities.append(vuln)
            
            # Create vulnerability details table
            if actual_vulnerabilities:
                vuln_details_data = [
                    ['Severity', 'Type', 'Description', 'Location']
                ]
                
                # Sort by severity (critical first)
                severity_order = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}
                sorted_vulns = sorted(actual_vulnerabilities, 
                                    key=lambda x: severity_order.get(x.get('severity', 'info'), 5))
                
                for vuln in sorted_vulns:
                    severity = vuln.get('severity', 'Unknown').upper()
                    vuln_type = vuln.get('type', 'Unknown')
                    description = vuln.get('description', 'No description available')
                    location = vuln.get('path', '/')
                    
                    # Truncate long descriptions
                    if len(description) > 60:
                        description = description[:60] + "..."
                    
                    # Add severity emoji
                    severity_emoji = {
                        'CRITICAL': '🚨',
                        'HIGH': '🔴', 
                        'MEDIUM': '🟡',
                        'LOW': '🟢',
                        'INFO': 'ℹ️'
                    }
                    severity_display = f"{severity_emoji.get(severity, '')} {severity}"
                    
                    vuln_details_data.append([
                        severity_display,
                        vuln_type,
                        description,
                        location
                    ])
                
                # Create table with proper column widths
                vuln_details_table = Table(vuln_details_data, colWidths=[1.2*inch, 1.5*inch, 2.8*inch, 1*inch])
                vuln_details_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('TOPPADDING', (0, 1), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                
                story.append(vuln_details_table)
                story.append(Spacer(1, 20))
            
            # NEW: Positive Security Features Section
            if positive_features:
                story.append(Paragraph("✅ Positive Security Features Detected", subtitle_style))
                story.append(Spacer(1, 10))
                
                positive_data = [['Feature Type', 'Description']]
                for feature in positive_features:
                    feature_type = feature.get('type', 'Unknown')
                    description = feature.get('description', 'No description available')
                    if len(description) > 80:
                        description = description[:80] + "..."
                    positive_data.append([feature_type, description])
                
                positive_table = Table(positive_data, colWidths=[2*inch, 4*inch])
                positive_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkgreen),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightgreen),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                
                story.append(positive_table)
                story.append(Spacer(1, 20))
            
            # NEW: Informational Findings Section
            if info_findings:
                story.append(Paragraph("ℹ️ Informational Findings", subtitle_style))
                story.append(Spacer(1, 10))
                
                info_data = [['Type', 'Description', 'Location']]
                for finding in info_findings:
                    finding_type = finding.get('type', 'Unknown')
                    description = finding.get('description', 'No description available')
                    location = finding.get('path', '/')
                    if len(description) > 70:
                        description = description[:70] + "..."
                    info_data.append([finding_type, description, location])
                
                info_table = Table(info_data, colWidths=[1.5*inch, 3.5*inch, 1*inch])
                info_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                
                story.append(info_table)
                story.append(Spacer(1, 20))
        
    except Exception as e:
        story.append(Paragraph(f"Error parsing vulnerability details: {str(e)}", normal_style))
        story.append(Spacer(1, 10))
    
    # AI Recommendation Section (if available)
    if scan.recommendation:
        story.append(Paragraph("🤖 AI Security Analysis & Recommendations", subtitle_style))
        story.append(Spacer(1, 10))
        
        # Process recommendation text
        recommendation_text = scan.recommendation
        
        # Split recommendation into paragraphs and process formatting
        paragraphs = recommendation_text.split('\n\n')
        
        for paragraph in paragraphs:
            if paragraph.strip():
                # Remove markdown-style formatting and clean up
                clean_paragraph = paragraph.strip()
                clean_paragraph = clean_paragraph.replace('**', '')
                clean_paragraph = clean_paragraph.replace('*', '•')
                clean_paragraph = clean_paragraph.replace('🤖', '')
                clean_paragraph = clean_paragraph.replace('📊', '• ')
                clean_paragraph = clean_paragraph.replace('🚨', '! ')
                clean_paragraph = clean_paragraph.replace('✅', '✓ ')
                clean_paragraph = clean_paragraph.replace('⚠️', '⚠ ')
                clean_paragraph = clean_paragraph.replace('🔴', '• ')
                clean_paragraph = clean_paragraph.replace('🟠', '• ')
                clean_paragraph = clean_paragraph.replace('🟡', '• ')
                clean_paragraph = clean_paragraph.replace('🟢', '• ')
                clean_paragraph = clean_paragraph.replace('🔵', '• ')
                
                # Handle special sections
                if clean_paragraph.startswith('CRITICAL') or clean_paragraph.startswith('EMERGENCY'):
                    # Critical sections in red
                    critical_style = ParagraphStyle(
                        'Critical',
                        parent=normal_style,
                        textColor=colors.darkred,
                        fontName='Helvetica-Bold'
                    )
                    story.append(Paragraph(clean_paragraph, critical_style))
                elif any(keyword in clean_paragraph.upper() for keyword in ['EXCELLENT', 'OUTSTANDING', 'GOOD']):
                    # Positive sections in green
                    positive_style = ParagraphStyle(
                        'Positive',
                        parent=normal_style,
                        textColor=colors.darkgreen,
                        fontName='Helvetica-Bold'
                    )
                    story.append(Paragraph(clean_paragraph, positive_style))
                else:
                    # Normal text
                    story.append(Paragraph(clean_paragraph, normal_style))
                
                story.append(Spacer(1, 10))
    
    # Footer
    story.append(Spacer(1, 30))
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.grey,
        alignment=1
    )
    story.append(Paragraph(f"Report generated on {datetime.now().strftime('%d %B %Y at %H:%M:%S')}", footer_style))
    story.append(Paragraph("Comprehensive Security Assessment Report - Vulnerability Scanner", footer_style))
    
    # Build PDF
    doc.build(story)
    
    return response

@login_required
def delete_scan_result(request, scan_id):
    # Only allow user to delete their own scan results
    scan = get_object_or_404(ScanResult, id=scan_id, user=request.user)
    scan.delete()
    messages.success(request, "Hasil pemindaian berhasil dihapus!")
    return redirect('scan_history')

@login_required
def clear_all_history(request):
    if request.method == 'POST':
        # Only delete scan results for the logged-in user
        ScanResult.objects.filter(user=request.user).delete()
        messages.success(request, "Semua riwayat pemindaian berhasil dihapus!")
    return redirect('scan_history')