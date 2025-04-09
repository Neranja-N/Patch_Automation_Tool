import { Component, OnInit, ViewChild, AfterViewInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import { MatTableDataSource, MatTableModule } from '@angular/material/table';
import { MatPaginator, MatPaginatorModule } from '@angular/material/paginator';
import { MatSort, MatSortModule } from '@angular/material/sort';
import { EndpointService } from '../services/endpoint.service';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatTooltipModule } from '@angular/material/tooltip';

@Component({
  selector: 'app-soft-installed',
  standalone: true,
  imports: [
    CommonModule,
    RouterModule,
    MatTableModule,
    MatPaginatorModule,
    MatSortModule,
    MatCardModule,
    MatButtonModule,
    MatIconModule,
    MatProgressSpinnerModule,
    MatFormFieldModule,
    MatInputModule,
    MatTooltipModule,
    MatSnackBarModule
  ],
  templateUrl: './soft-installed.component.html',
  styleUrls: ['./soft-installed.component.css']
})
export class SoftInstalledComponent implements OnInit, AfterViewInit {
  displayedColumns: string[] = ['software_name', 'version', 'install_date', 'update_available'];
  dataSource = new MatTableDataSource<any>([]);
  endpoints: any[] = [];
  loading = true;
  error = false;

  @ViewChild(MatPaginator) paginator!: MatPaginator;
  @ViewChild(MatSort) sort!: MatSort;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private endpointService: EndpointService,
    private snackBar: MatSnackBar
  ) {}

  ngOnInit(): void {
    this.loadSoftwareList();
  }

  ngAfterViewInit() {
    this.dataSource.paginator = this.paginator;
    this.dataSource.sort = this.sort;
  }

  loadSoftwareList(): void {
    this.loading = true;
    this.error = false;

    this.endpointService.getAllEndpointSoftware().subscribe({
      next: (response) => {
        // Assuming the response has an "endpoints" array
        this.endpoints = response.endpoints;
        // Flatten all software into a single list for the table
        const allSoftware = this.endpoints.flatMap(endpoint => 
          endpoint.software.map((sw: any) => ({
            ...sw,
            computer_name: endpoint.computer_name,
            ip_address: endpoint.ip_address
          }))
        );
        this.dataSource.data = allSoftware;
        this.loading = false;
      },
      error: (error) => {
        console.error('Error loading software list:', error);
        this.error = true;
        this.loading = false;
        this.snackBar.open('Error loading software list', 'Close', { duration: 5000 });
      }
    });
  }

  applyFilter(event: Event): void {
    const filterValue = (event.target as HTMLInputElement).value;
    this.dataSource.filter = filterValue.trim().toLowerCase();

    if (this.dataSource.paginator) {
      this.dataSource.paginator.firstPage();
    }
  }

  refreshData(): void {
    this.loadSoftwareList();
  }
}