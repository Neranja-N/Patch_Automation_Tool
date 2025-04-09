import { Component, OnInit } from '@angular/core';
import { HttpClientModule } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { EndpointService } from '../../services/endpoint.service';
import { environment } from '../../../environments/environment';

interface OsUpdate {
  ip_address?: string;  // Made optional
  os_name: string;
  kb_code: string;
  current_kb_version?: string;  // Made optional
  available_updates: string;
  approved: boolean;
}

@Component({
  selector: 'app-approved-updates',
  standalone: true,
  imports: [CommonModule, FormsModule, HttpClientModule],
  templateUrl: './approved-updates.component.html',
  styleUrls: ['./approved-updates.component.css']
})
export class ApprovedUpdatesComponent implements OnInit {
  osUpdates: OsUpdate[] = [];
  apiUrl = 'http://localhost:8181/api';

  constructor(private endpointService: EndpointService) {}

  ngOnInit(): void {
    this.fetchOsUpdates();
  }

  fetchOsUpdates(): void {
    this.endpointService.getavailableupdates().subscribe(
      (response: { status: string; updates: any[] }) => {
        if (response.status === 'success') {
          this.osUpdates = response.updates.map(update => ({
            ip_address: "N/A",  
            os_name: update.title, 
            current_kb_version: "Unknown", 
            available_updates: update.kb_code, 
            kb_code: update.kb_code,
            approved: false, 
          }));
        }
      },
      (error) => {
        console.error('Error fetching OS updates:', error);
      }
    );
  }

  // approveUpdate(kbCode: string): void {
  //   this.endpointService.approveOsUpdates({ kbCode }).subscribe(
  //     (response: { status: string; message: string }) => {
  //       if (response.status === 'success') {
  //         console.log(response.message);
  //         this.fetchOsUpdates(); // Refresh the list after approval
  //       }
  //     },
  //     (error) => {
  //       console.error('Error approving update:', error);
  //     }
  //   );
  // }

  approveUpdate(kbCode: string): void {
    this.endpointService.approveOsUpdates(kbCode).subscribe({
      next: (response) => {
        console.log('Approval successful:', response);
        this.fetchOsUpdates();
      },
      error: (error) => {
        console.error('Approval failed:', error);
      }
    });
  }
  
}
