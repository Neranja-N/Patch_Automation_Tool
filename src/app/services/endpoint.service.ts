import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse, HttpHeaders  } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { environment } from '../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class EndpointService {
  private apiUrl = environment.apiUrl;

  constructor(private http: HttpClient) {}
  
  // Collect endpoints with authentication
  collectEndpoints(ipAddresses: string, username: string, password: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/collect`, {
      ip_addresses: ipAddresses,
      username: username,
      password: password
    }).pipe(catchError(this.handleError));
  }

  // Get all endpoints
  getAllEndpoints(): Observable<any> {
    const headers = new HttpHeaders({
      'ngrok-skip-browser-warning': 'true', 
    });
    return this.http.get(`${this.apiUrl}/GetData`,{ headers }).pipe(catchError(this.handleError));
  }

  // Get a specific endpoint by ID
  getEndpointById(id: number): Observable<any> {
    return this.http.get(`${this.apiUrl}/endpoints/${id}`).pipe(catchError(this.handleError));
  }

  // Get endpoint by IP address
  getEndpointByIp(ipAddress: string): Observable<any> {
    return this.http.get(`${this.apiUrl}/endpoints/${ipAddress}/latest`).pipe(catchError(this.handleError));
  }

  // Get software details of an endpoint
  getEndpointSoftware(id: number): Observable<any> {
    return this.http.get(`${this.apiUrl}/endpoints/${id}/software`).pipe(catchError(this.handleError));
  }

  getAllEndpointSoftware(): Observable<any> {
    return this.http.get(`${this.apiUrl}/endpoints/softwareAll`).pipe(catchError(this.handleError));
  }

  // Get system statistics
  getStats(): Observable<any> {
    const headers = new HttpHeaders({
      'ngrok-skip-browser-warning': 'true', 
    });
    return this.http.get(`${this.apiUrl}/counts`,{ headers }).pipe(catchError(this.handleError));
  }

  // Check if API is running
  healthCheck(): Observable<any> {
    return this.http.get(`${this.apiUrl}/health`).pipe(catchError(this.handleError));
  }

  // Fetch available OS updates
  getavailableupdates(): Observable<any> {
    const headers = new HttpHeaders({
      'ngrok-skip-browser-warning': 'true', 
    });
    return this.http.get(`${this.apiUrl}/get_os_updates`, { headers }).pipe(catchError(this.handleError));
  }

  // Approve an OS update (Ensure API expects `available_updates`)
  approveOsUpdates(kbCode: string): Observable<any> {
    const headers = new HttpHeaders({
      'Content-Type': 'application/json',
      'ngrok-skip-browser-warning': 'true'
    });
  
    // Match the payload key to what your backend expects
    const payload = { kb_code: kbCode };
  
    return this.http.post(
      `${this.apiUrl}/approve_os_updates`,
      payload,
      { headers }
    ).pipe(
      catchError(this.handleError)
    );
  }

  // Improved error handling
  private handleError(error: HttpErrorResponse) {
    console.error('API Error:', error);
    let errorMessage = 'Unknown error!';
    if (error.error instanceof ErrorEvent) {
      errorMessage = `Client-side error: ${error.error.message}`;
    } else {
      errorMessage = `Server error: ${error.status} - ${error.message}`;
    }
    return throwError(() => new Error(errorMessage));
  }

  getavailableupdatessof(): Observable<any> {
    const headers = new HttpHeaders({
      'ngrok-skip-browser-warning': 'true', 
    });
    return this.http.get(`${this.apiUrl}/pending-updates-sof`, { headers }).pipe(catchError(this.handleError));
  }

  

  // Approve a software update
  approveUpdate(softwareName: string, currentVersion: string): Observable<any> {
    const headers = new HttpHeaders({
      'Content-Type': 'application/json',
      'ngrok-skip-browser-warning': 'true'
    });

    const payload = { software_name: softwareName, current_version: currentVersion };

    return this.http.post(`${this.apiUrl}/approve-update`, payload, { headers })
      .pipe(catchError(this.handleError));
  }

  getOSDoneupdates(): Observable<any> {
    const headers = new HttpHeaders({
      'ngrok-skip-browser-warning': 'true', 
    });
    return this.http.get(`${this.apiUrl}/get_done_os_updates`, { headers }).pipe(catchError(this.handleError));
  }

  getSoftwareDoneUpdates(): Observable<any> {
    const headers = new HttpHeaders({
      'ngrok-skip-browser-warning': 'true', 
    });
    return this.http.get(`${this.apiUrl}/get_done_software_updates`, { headers }).pipe(catchError(this.handleError));
  }
}
