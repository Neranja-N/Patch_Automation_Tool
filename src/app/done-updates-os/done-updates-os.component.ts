import { Component, OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { EndpointService } from '../services/endpoint.service';
import { CommonModule } from '@angular/common'; // Import CommonModule
import * as XLSX from 'xlsx'; // Import xlsx
import { saveAs } from 'file-saver';

@Component({
  selector: 'app-done-updates-os',
  standalone: true, // Ensure this is present if using standalone components
  imports: [CommonModule], // Add CommonModule here
  templateUrl: './done-updates-os.component.html',
  styleUrls: ['./done-updates-os.component.css']
})
export class DoneUpdatesOsComponent implements OnInit {
  updates: any[] = [];
  error: string | null = null;

  constructor(private http: HttpClient, private endpointService: EndpointService) {}

  ngOnInit(): void {
    this.fetchDoneUpdates();
  }

  fetchDoneUpdates(): void {
    this.endpointService.getOSDoneupdates().subscribe(
      (response: { error: string | null; status: string; updates: any[] }) => {
        console.log('Full response:', response); // Debug
        if (response.status === 'success') {
          this.updates = response.updates;
          console.log('Updates:', this.updates); // Debug
        } else {
          this.error = response.error;
        }
      },
      (error) => {
        console.error('Error fetching OS updates:', error);
        this.error = 'Failed to load updates: ' + error.message;
      }
    );
  }

  exportToExcel(): void {
    if (this.updates.length === 0) {
      this.error = 'No data to export';
      return;
    }

    // Prepare data for Excel
    const excelData = this.updates.map(update => ({
      'IP Address': update.ip_address,
      'KB Code': update.kb_code,
      'Title': update.title,
      'Size (MB)': update.size_mb,
      'Reboot Required': update.reboot_required ? 'Yes' : 'No',
      'Approved': update.approved ? 'Yes' : 'No',
      'Check Time': update.check_time
    }));

    // Create worksheet and workbook
    const ws: XLSX.WorkSheet = XLSX.utils.json_to_sheet(excelData);
    const wb: XLSX.WorkBook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Completed OS Updates');

    // Generate and download Excel file
    const excelBuffer: any = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
    const data: Blob = new Blob([excelBuffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
    saveAs(data, 'Completed_OS_Updates.xlsx');
  }
}