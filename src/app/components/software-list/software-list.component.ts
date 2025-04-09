import { Component, OnInit, ViewChild, AfterViewInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import { MatTableDataSource, MatTableModule } from '@angular/material/table';
import { MatPaginator, MatPaginatorModule } from '@angular/material/paginator';
import { MatSort, MatSortModule } from '@angular/material/sort';
import { EndpointService } from '../../services/endpoint.service';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatTooltipModule } from '@angular/material/tooltip';

@Component({
  selector: 'app-software-list',
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
  templateUrl: './software-list.component.html',
  styleUrls: ['./software-list.component.css']
})
export class SoftwareListComponent implements OnInit, AfterViewInit {
  endpointId!: number;
  endpointInfo: any = {};
  displayedColumns: string[] = ['software_name', 'version', 'vendor', 'install_date', 'source'];
  dataSource = new MatTableDataSource<any>([]);
  loading = true;
  error = false;

  @ViewChild(MatPaginator) paginator!: MatPaginator;
  @ViewChild(MatSort) sort!: MatSort;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private endpointService: EndpointService,
    private snackBar: MatSnackBar
  ) { }

  ngOnInit(): void {
    this.route.paramMap.subscribe(params => {
      const id = params.get('id');
      if (id) {
        this.endpointId = +id;
        this.loadSoftwareList();
      } else {
        this.router.navigate(['/endpoints']);
      }
    });
  }

  ngAfterViewInit() {
    this.dataSource.paginator = this.paginator;
    this.dataSource.sort = this.sort;
  }

  loadSoftwareList(): void {
    this.loading = true;
    this.error = false;

    this.endpointService.getEndpointSoftware(this.endpointId).subscribe({
      next: (response) => {
        this.endpointInfo = {
          id: this.endpointId,
          ip_address: response.ip_address,
          computer_name: response.computer_name
        };
        this.dataSource.data = response.software;
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

  goBack(): void {
    this.router.navigate(['/endpoints', this.endpointId]);
  }

  refreshData(): void {
    this.loadSoftwareList();
  }
}
