import { api, type RequestOptions } from './client';

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
  get(options?: RequestOptions): Promise<DashboardData> {
    return api.get<DashboardData>('/dashboard', options);
  },
};
