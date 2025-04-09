import { ComponentFixture, TestBed } from '@angular/core/testing';

import { DoneUpdatesSofComponent } from './done-updates-sof.component';

describe('DoneUpdatesSofComponent', () => {
  let component: DoneUpdatesSofComponent;
  let fixture: ComponentFixture<DoneUpdatesSofComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [DoneUpdatesSofComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(DoneUpdatesSofComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
