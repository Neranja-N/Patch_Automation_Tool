import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import { EndpointService } from '../services/endpoint.service';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatTabsModule } from '@angular/material/tabs';
import { MatDividerModule } from '@angular/material/divider';
import { MatTooltipModule } from '@angular/material/tooltip';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ReactiveFormsModule } from '@angular/forms'; // Add this import

@Component({
  selector: 'app-new-endpoint',
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
    MatSnackBarModule,
    ReactiveFormsModule // Add this line
  ],
  templateUrl: './new-endpoint.component.html',
  styleUrl: './new-endpoint.component.css'
})


export class NewEndpointComponent implements OnInit{

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