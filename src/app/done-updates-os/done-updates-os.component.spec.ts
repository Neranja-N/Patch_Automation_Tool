import { ComponentFixture, TestBed } from '@angular/core/testing';

import { DoneUpdatesOsComponent } from './done-updates-os.component';

describe('DoneUpdatesOsComponent', () => {
  let component: DoneUpdatesOsComponent;
  let fixture: ComponentFixture<DoneUpdatesOsComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [DoneUpdatesOsComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(DoneUpdatesOsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
