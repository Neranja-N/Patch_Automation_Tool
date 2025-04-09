import { Routes } from '@angular/router';
import { DashboardComponent } from './components/dashboard/dashboard.component';
import { EndpointListComponent } from './components/endpoint-list/endpoint-list.component';
import { EndpointDetailComponent } from './components/endpoint-detail/endpoint-detail.component';
import { SoftwareListComponent } from './components/software-list/software-list.component';
import { StatsComponent } from './components/stats/stats.component';
import { AdminLoginComponent } from './components/admin-login/admin-login.component';
import { ApprovedUpdatesComponent } from './components/approved-updates/approved-updates.component';
import { OverviewComponent } from './overview/overview.component';
import { UpdatedoneComponent } from './updatedone/updatedone.component';
import { NewEndpointComponent } from './new-endpoint/new-endpoint.component';
import { ApprovedUpdatesSoftComponent } from './approved-updates-soft/approved-updates-soft.component';
import { DoneUpdatesOsComponent } from './done-updates-os/done-updates-os.component';
import { DoneUpdatesSofComponent } from './done-updates-sof/done-updates-sof.component';
import { SoftInstalledComponent } from './soft-installed/soft-installed.component';


export const routes: Routes = [
  { path: '', redirectTo: '/login', pathMatch: 'full' },
  { 
    path: 'dashboard', 
    component: DashboardComponent,
    children: [
      { path: 'overview', component: OverviewComponent },
      { path: 'endpoints', component: NewEndpointComponent }, 
      { path: 'pendinupdates', component: ApprovedUpdatesComponent },
      { path: 'pendinupdatesSof', component: ApprovedUpdatesSoftComponent },
      { path: 'donedatesos', component: DoneUpdatesOsComponent },
      { path: 'doneupdatesSof', component: DoneUpdatesSofComponent },
      { path: 'softinstall', component: SoftInstalledComponent },
      { path: '', redirectTo: 'overview', pathMatch: 'full' }
    ]
  },
  { path: 'login', component: AdminLoginComponent },
  { path: 'approved', component: ApprovedUpdatesComponent },
  { path: 'stats', component: StatsComponent },
  { path: '**', redirectTo: '/dashboard' },
];
