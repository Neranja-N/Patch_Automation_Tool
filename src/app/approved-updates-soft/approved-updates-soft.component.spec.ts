import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ApprovedUpdatesSoftComponent } from './approved-updates-soft.component';

describe('ApprovedUpdatesSoftComponent', () => {
  let component: ApprovedUpdatesSoftComponent;
  let fixture: ComponentFixture<ApprovedUpdatesSoftComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ApprovedUpdatesSoftComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ApprovedUpdatesSoftComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
