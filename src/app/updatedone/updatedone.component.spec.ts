import { ComponentFixture, TestBed } from '@angular/core/testing';

import { UpdatedoneComponent } from './updatedone.component';

describe('UpdatedoneComponent', () => {
  let component: UpdatedoneComponent;
  let fixture: ComponentFixture<UpdatedoneComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [UpdatedoneComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(UpdatedoneComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
