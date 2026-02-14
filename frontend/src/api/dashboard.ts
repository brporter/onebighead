import { api } from './client';

export interface DailyView {
  date: string;
  viewCount: number;
}

export interface DashboardData {
  collectionCount: number;
  itemCount: number;
  imageCount: number;
  imageTotalSizeBytes: number;
  dailyViews: DailyView[];
}

export const dashboardApi = {
  get(): Promise<DashboardData> {
    return api.get<DashboardData>('/dashboard');
  },
};
