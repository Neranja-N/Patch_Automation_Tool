import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ApprovedUpdatesComponent } from './approved-updates.component';

describe('ApprovedUpdatesComponent', () => {
  let component: ApprovedUpdatesComponent;
  let fixture: ComponentFixture<ApprovedUpdatesComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ApprovedUpdatesComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ApprovedUpdatesComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
