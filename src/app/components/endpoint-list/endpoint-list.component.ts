import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { EndpointService } from '../../services/endpoint.service';
import { ReactiveFormsModule, FormGroup, FormBuilder, Validators } from '@angular/forms';

@Component({
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule], // Combined imports
  selector: 'app-endpoint-list',
  templateUrl: './endpoint-list.component.html',
  styleUrls: ['./endpoint-list.component.css'],
})
export class EndpointListComponent implements OnInit {
  collectionForm: FormGroup;
  endpoints: any[] = [];
  loading = false;
  error = '';

  constructor(
    private endpointService: EndpointService,
    private fb: FormBuilder
  ) {
    this.collectionForm = this.fb.group({
      ipAddresses: ['', Validators.required],
      username: ['', Validators.required],
      password: ['', Validators.required],
    });
  }

  ngOnInit(): void {
    this.loadEndpoints();
  }

  loadEndpoints(): void {
    this.endpointService.getAllEndpoints().subscribe(
      (response) => {
        
        this.endpoints = response.devices.map((device: any) => ({
          ip_address: device.IP_Address,
          computer_name: device.Model || 'Unknown',
          os_name: device.OS_Name.split('|')[0] || 'Unknown', 
          os_version: device.OS_Name.split('|')[1] || 'Unknown', 
          cpu: device.Processor || 'Unknown',
          ram_gb: device.RAM_Size || 'Unknown',
          collection_time: device.Collection_Time
        }));
      },
      (error) => {
        this.error = 'Failed to load endpoints: ' + error.message;
      }
    );
  }
  
  // collectData(): void {
  //   if (this.collectionForm.valid) {
  //     this.loading = true;
  //     this.error = ''; // Reset error message
  //     const { ipAddresses, username, password } = this.collectionForm.value;

  //     this.endpointService.collectEndpoints(ipAddresses, username, password).subscribe(
  //       () => {
  //         this.loading = false;
  //         //this.loadEndpoints();
  //       },
  //       (error) => {
  //         this.loading = false;
  //         this.error = 'Collection failed: ' + error.message;
  //       }
  //     );
  //   }
  // }

  collectData(): void {
    if (this.collectionForm.valid) {
      this.loading = true;
      this.error = ''; // Reset error message
      const { ipAddresses, username, password } = this.collectionForm.value;
  
      this.endpointService.collectEndpoints(ipAddresses, username, password).subscribe(
        (response) => {
          this.loading = false;
          
          if (response.successful_data) {
            alert('Succefull Data Inserted................!');
            this.loadEndpoints();
            // Assign collected data to the endpoints array
            
          }
        },
        (error) => {
          this.loading = false;
          this.error = 'Collection failed: ' + error.message;
        }
      );
    }
  }
  
}

export interface EndpointData {
  IP_Address: string;
  Collection_Time: string;
  Collection_Status: string;
  OS_Info: {
    name?: string;
    version?: string;
  };
  System_Info: {
    cpu?: string;
    model?: string;
    ram_gb?: number;
  };
}
