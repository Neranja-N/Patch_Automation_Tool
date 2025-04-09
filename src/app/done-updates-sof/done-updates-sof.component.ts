import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { EndpointService } from '../services/endpoint.service';
import * as XLSX from 'xlsx'; // Import xlsx
import { saveAs } from 'file-saver';

@Component({
  selector: 'app-done-updates-sof',
  standalone: true,
  imports: [CommonModule], // Include CommonModule for *ngIf and *ngFor
  templateUrl: './done-updates-sof.component.html',
  styleUrls: ['./done-updates-sof.component.css']
})
export class DoneUpdatesSofComponent implements OnInit {
  updates: any[] = [];
  error: string | null = null;

  constructor(private endpointService: EndpointService) {}

  ngOnInit(): void {
    this.fetchDoneUpdates();
  }

  fetchDoneUpdates(): void {
    this.endpointService.getSoftwareDoneUpdates().subscribe(
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
        console.error('Error fetching software updates:', error);
        this.error = 'Failed to load updates: ' + error.message;
      }
    );
  }

  exportToExcel(): void {
    // Prepare data for Excel (map updates to a simpler format if needed)
    const excelData = this.updates.map(update => ({
      'IP Address': update.ip_address,
      'Software Name': update.software_name,
      'Current Version': update.current_version,
      'Available Version': update.available_version,
      'Check Time': update.check_time,
      'Approved': update.approved ? 'Yes' : 'No'
    }));

    // Create a worksheet
    const ws: XLSX.WorkSheet = XLSX.utils.json_to_sheet(excelData);

    // Create a workbook and append the worksheet
    const wb: XLSX.WorkBook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Completed Software Updates');

    // Generate Excel file and download
    const excelBuffer: any = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
    const data: Blob = new Blob([excelBuffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
    saveAs(data, 'Completed_Software_Updates.xlsx');
  }
}