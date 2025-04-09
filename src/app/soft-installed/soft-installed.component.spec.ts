import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SoftInstalledComponent } from './soft-installed.component';

describe('SoftInstalledComponent', () => {
  let component: SoftInstalledComponent;
  let fixture: ComponentFixture<SoftInstalledComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SoftInstalledComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(SoftInstalledComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
