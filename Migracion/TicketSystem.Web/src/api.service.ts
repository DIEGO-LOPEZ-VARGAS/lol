import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private http = inject(HttpClient);
  get<T = any>(path: string): Promise<T> { return firstValueFrom(this.http.get<T>(`/api${path}`, { withCredentials: true })); }
  post<T = any>(path: string, body: unknown = {}): Promise<T> { return firstValueFrom(this.http.post<T>(`/api${path}`, body, { withCredentials: true })); }
  put<T = any>(path: string, body: unknown): Promise<T> { return firstValueFrom(this.http.put<T>(`/api${path}`, body, { withCredentials: true })); }
  delete<T = any>(path: string): Promise<T> { return firstValueFrom(this.http.delete<T>(`/api${path}`, { withCredentials: true })); }
}
