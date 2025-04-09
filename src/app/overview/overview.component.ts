import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { EndpointService } from '../services/endpoint.service';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatTableModule } from '@angular/material/table';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatListModule } from '@angular/material/list';
import { MatMenuModule } from '@angular/material/menu';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { DatePipe } from '@angular/common';
import { Router, RouterModule } from '@angular/router';


@Component({
  selector: 'app-overview',
  imports: [CommonModule,
    RouterModule,
    MatCardModule,
    MatButtonModule,
    MatIconModule,
    MatTableModule,
    MatSnackBarModule,
    MatSidenavModule,
    MatToolbarModule,
    MatListModule,
    MatMenuModule,
    MatProgressSpinnerModule,
    DatePipe],
  templateUrl: './overview.component.html',
  styleUrl: './overview.component.css'
})
export class OverviewComponent {
  stats: any = {}; // Store the statistics (NetworkScanResults_count, PendingUpdates_count)
  devices: any[] = []; // Store the list of devices
  displayedColumns: string[] = ['ip_address', 'model', 'os_name', 'processor', 'ram_size', 'collection_time'];
  loading = true;

  constructor(
      private endpointService: EndpointService,
      private snackBar: MatSnackBar,
      private router: Router
    ) { }
  
    ngOnInit(): void {
      this.loadDashboardData();
    }
  
    loadDashboardData(): void {
      this.loading = true;
      
      // Fetching statistics (counts)
      this.endpointService.getStats().subscribe({
        next: (response: any) => {
          this.stats = response;
          this.loading = false;
        },
        error: (error: any) => {
          console.error('Error loading stats:', error);
          this.snackBar.open('Error loading statistics', 'Close', { duration: 5000 });
          this.loading = false;
        }
      });
  
      // Fetching list of devices
      this.endpointService.getAllEndpoints().subscribe({
        next: (response: { devices: any[] }) => {
          // Define the IP addresses to exclude
          const excludedIps = ['192.168.8.100', '192.168.8.150'];
          
          // Filter out devices with excluded IP addresses
          this.devices = response.devices.filter(device => 
            !excludedIps.includes(device.IP_Address)
          );
        },
        error: (error: any) => {
          console.error('Error loading devices:', error);
          this.snackBar.open('Error loading devices', 'Close', { duration: 5000 });
        }
      });
    }

}
