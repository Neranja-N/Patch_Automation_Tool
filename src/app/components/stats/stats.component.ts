import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { EndpointService } from '../../services/endpoint.service';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatTableModule } from '@angular/material/table';
import { NgChartsModule } from 'ng2-charts';

@Component({
  selector: 'app-stats',
  standalone: true,
  imports: [
    CommonModule,
    MatCardModule,
    MatButtonModule,
    MatIconModule,
    MatProgressSpinnerModule,
    MatTableModule,
    MatSnackBarModule,
    NgChartsModule
  ],
  templateUrl: './stats.component.html',
  styleUrls: ['./stats.component.css']
})
export class StatsComponent implements OnInit {
  stats: any = {};
  loading = true;
  error = false;

  // Chart data
  osChartData: any = {
    labels: [],
    datasets: [
      {
        data: [],
        backgroundColor: [
          '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF',
          '#FF9F40', '#8BC34A', '#607D8B', '#E91E63', '#3F51B5'
        ]
      }
    ]
  };

  manufacturerChartData: any = {
    labels: [],
    datasets: [
      {
        data: [],
        backgroundColor: [
          '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF6384',
          '#8BC34A', '#607D8B', '#E91E63', '#3F51B5', '#FF9F40'
        ]
      }
    ]
  };

  vendorChartData: any = {
    labels: [],
    datasets: [
      {
        label: 'Software Count',
        data: [],
        backgroundColor: '#3f51b5'
      }
    ]
  };

  constructor(
    private endpointService: EndpointService,
    private snackBar: MatSnackBar
  ) { }

  ngOnInit(): void {
    this.loadStats();
  }

  loadStats(): void {
    this.loading = true;
    this.error = false;

    this.endpointService.getStats().subscribe({
      next: (response) => {
        this.stats = response.stats;
        
        // Prepare chart data for OS distribution
        this.osChartData.labels = this.stats.os_distribution.map((item: any) => item.name);
        this.osChartData.datasets[0].data = this.stats.os_distribution.map((item: any) => item.count);
        
        // Prepare chart data for manufacturer distribution
        this.manufacturerChartData.labels = this.stats.manufacturer_distribution.map((item: any) => item.name);
        this.manufacturerChartData.datasets[0].data = this.stats.manufacturer_distribution.map((item: any) => item.count);
        
        // Prepare chart data for vendor distribution
        this.vendorChartData.labels = this.stats.top_vendors.map((item: any) => item.name);
        this.vendorChartData.datasets[0].data = this.stats.top_vendors.map((item: any) => item.count);
        
        this.loading = false;
      },
      error: (error) => {
        console.error('Error loading stats:', error);
        this.error = true;
        this.loading = false;
        this.snackBar.open('Error loading statistics', 'Close', { duration: 5000 });
      }
    });
  }

  refreshData(): void {
    this.loadStats();
  }
}
