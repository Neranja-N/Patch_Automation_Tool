import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import { EndpointService } from '../../services/endpoint.service';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatTabsModule } from '@angular/material/tabs';
import { MatDividerModule } from '@angular/material/divider';
import { MatTooltipModule } from '@angular/material/tooltip';

@Component({
  selector: 'app-endpoint-detail',
  standalone: true,
  imports: [
    CommonModule,
    RouterModule,
    MatCardModule,
    MatButtonModule,
    MatIconModule,
    MatProgressSpinnerModule,
    MatTabsModule,
    MatDividerModule,
    MatTooltipModule,
    MatSnackBarModule
  ],
  templateUrl: './endpoint-detail.component.html',
  styleUrls: ['./endpoint-detail.component.css']
})
export class EndpointDetailComponent implements OnInit {
  endpointId!: number;
  endpoint: any = {};
  loading = true;
  error = false;

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
        this.loadEndpointDetails();
      } else {
        this.router.navigate(['/endpoints']);
      }
    });
  }

  loadEndpointDetails(): void {
    this.loading = true;
    this.error = false;

    this.endpointService.getEndpointById(this.endpointId).subscribe({
      next: (response) => {
        this.endpoint = response.endpoint;
        this.loading = false;
      },
      error: (error) => {
        console.error('Error loading endpoint details:', error);
        this.error = true;
        this.loading = false;
        this.snackBar.open('Error loading endpoint details', 'Close', { duration: 5000 });
      }
    });
  }

  goBack(): void {
    this.router.navigate(['/endpoints']);
  }

  viewSoftware(): void {
    this.router.navigate(['/endpoints', this.endpointId, 'software']);
  }

  refreshData(): void {
    this.loadEndpointDetails();
  }
}
