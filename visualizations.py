import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
from typing import List, Dict
import io
import base64

class SecurityVisualizer:
    """Create visualizations for security incidents"""
    
    def create_timeline(self, incidents: List[Dict]) -> str:
        """Create attack timeline visualization with plot graphs"""
        
        if not incidents:
            return None
        
        # Extract timestamps and types
        timeline_data = []
        for incident in incidents:
            for event in incident.get('events', [])[:5]:  # Limit to 5 events per incident
                timestamp = event.get('timestamp')
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        timeline_data.append({
                            'time': dt,
                            'type': incident['type'],
                            'severity': incident['severity']
                        })
                    except:
                        pass
        
        if not timeline_data:
            return None
        
        # Sort by time
        timeline_data.sort(key=lambda x: x['time'])
        
        # Create figure
        fig, ax = plt.subplots(figsize=(12, 6))
        
        # Color mapping
        severity_colors = {
            'CRITICAL': '#d32f2f',
            'HIGH': '#f57c00',
            'MEDIUM': '#fbc02d',
            'LOW': '#388e3c'
        }
        
        # Plot events
        for i, event in enumerate(timeline_data):
            color = severity_colors.get(event['severity'], '#757575')
            ax.scatter(event['time'], i, c=color, s=200, alpha=0.7, edgecolors='black', linewidths=1.5)
            ax.text(event['time'], i, f" {event['type']}", 
                   verticalalignment='center', fontsize=9, fontweight='bold')
        
        # Format
        ax.set_xlabel('Time', fontsize=12, fontweight='bold')
        ax.set_ylabel('Event Sequence', fontsize=12, fontweight='bold')
        ax.set_title('Security Incident Timeline', fontsize=14, fontweight='bold', pad=20)
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        ax.grid(True, alpha=0.3, linestyle='--')
        
        # Remove y-axis ticks
        ax.set_yticks([])
        
        # Legend
        legend_elements = [
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='#d32f2f', 
                      markersize=10, label='CRITICAL'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='#f57c00', 
                      markersize=10, label='HIGH'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='#fbc02d', 
                      markersize=10, label='MEDIUM'),
        ]
        ax.legend(handles=legend_elements, loc='upper right')
        
        plt.tight_layout()
        
        # Save to file
        output_path = f'outputs/attack_timeline_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png'
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_path
    
    def create_summary_chart(self, incidents: List[Dict]) -> str:
        """Create incident summary pie chart"""
        
        if not incidents:
            return None
        
        # Count by type
        type_counts = {}
        for incident in incidents:
            incident_type = incident['type']
            type_counts[incident_type] = type_counts.get(incident_type, 0) + 1
        
        # Create pie chart
        fig, ax = plt.subplots(figsize=(10, 8))
        
        colors = ['#d32f2f', '#f57c00', '#fbc02d', '#388e3c', '#1976d2', '#7b1fa2']
        
        wedges, texts, autotexts = ax.pie(
            type_counts.values(),
            labels=type_counts.keys(),
            autopct='%1.1f%%',
            colors=colors[:len(type_counts)],
            startangle=90,
            textprops={'fontsize': 11, 'fontweight': 'bold'}
        )
        
        ax.set_title('Incident Distribution by Type', fontsize=14, fontweight='bold', pad=20)
        
        plt.tight_layout()
        
        output_path = f'outputs/incident_summary_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png'
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return output_path
