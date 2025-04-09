import { Component, OnInit } from '@angular/core';
import { EndpointService } from '../services/endpoint.service';

import { HttpClientModule } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';



@Component({
  selector: 'app-approved-updates-soft',
  imports: [CommonModule, FormsModule, HttpClientModule],
  templateUrl: './approved-updates-soft.component.html',
  styleUrls: ['./approved-updates-soft.component.css']
})
export class ApprovedUpdatesSoftComponent implements OnInit {
  pendingUpdates: { software_name: string, current_version: string, available_version: string }[] = [];

  constructor(private endpointService: EndpointService) {}

  ngOnInit(): void {
    this.getPendingUpdates();
  }

  getPendingUpdates(): void {
    this.endpointService.getavailableupdatessof().subscribe(
      (updates: any[]) => {  
        this.pendingUpdates = updates;  
        console.log('Pending Updates:', this.pendingUpdates); 
      },
      (error) => {
        console.error('Error fetching updates:', error);
      }
    );
  }
  
  

  approveUpdate(softwareName: string, currentVersion: string): void {
    this.endpointService.approveUpdate(softwareName, currentVersion).subscribe(
      () => {
        // Remove approved update from the list
        this.pendingUpdates = this.pendingUpdates.filter(update => 
          !(update.software_name === softwareName && update.current_version === currentVersion)
        );
      },
      error => console.error('Error approving update:', error)
    );
  }
}
