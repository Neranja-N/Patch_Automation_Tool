import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common'; // Import CommonModule
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router'; // Import Router for navigation

@Component({
  selector: 'app-admin-login',
  standalone: true,
  imports: [CommonModule, FormsModule], // Add CommonModule here
  templateUrl: './admin-login.component.html',
  styleUrls: ['./admin-login.component.css']
})
export class AdminLoginComponent implements OnInit {
  username: string = '';
  password: string = '';
  errorMessage: string = '';
  nodes = Array(20); // For network background
  lines: { x1: number; y1: number; x2: number; y2: number }[] = [];

  constructor(private router: Router) {}

  ngOnInit(): void {
    this.generateConnections();
  }

  generateConnections(): void {
    const nodePositions = Array.from({ length: 20 }, () => ({
      x: Math.random() * window.innerWidth,
      y: Math.random() * window.innerHeight,
    }));

    for (let i = 0; i < 10; i++) {
      const node1 = nodePositions[Math.floor(Math.random() * nodePositions.length)];
      const node2 = nodePositions[Math.floor(Math.random() * nodePositions.length)];
      this.lines.push({
        x1: node1.x,
        y1: node1.y,
        x2: node2.x,
        y2: node2.y,
      });
    }
  }

  onSubmit() {
    if (this.username && this.password) {
      console.log('Login attempt:', { username: this.username, password: this.password });
      if (this.username === 'admin' && this.password === '1234') {
        this.router.navigate(['/dashboard']); // Redirect to approved-updates
       console.log('Login attempt:', { username: this.username, password: this.password });
      } else {
        this.errorMessage = 'Invalid username or password.';
      }
    } else {
      this.errorMessage = 'Please enter both username and password.';
    }
  }
}