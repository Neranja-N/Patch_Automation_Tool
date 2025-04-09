import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { EndpointService } from '../../services/endpoint.service';
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
import { Router, RouterModule, ActivatedRoute  } from '@angular/router';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [
    CommonModule,
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
    DatePipe
  ],
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css']
})
export class DashboardComponent implements OnInit {
  stats: any = {}; // Store the statistics (NetworkScanResults_count, PendingUpdates_count)
  devices: any[] = []; // Store the list of devices
  displayedColumns: string[] = ['ip_address', 'model', 'os_name', 'processor', 'ram_size', 'collection_time'];
  loading = true;

  constructor(
    private endpointService: EndpointService,
    private snackBar: MatSnackBar,
    private router: Router,
    private route: ActivatedRoute
  ) { }

  ngOnInit(): void {
    
  }

  


  navigateTo(route: string) {
    // Use relative navigation since routes are nested
    this.router.navigate([route], { relativeTo: this.route });
  }
}