// Client-safe API wrapper that only makes HTTP requests
// No direct Redis or server-side imports

export interface MetaAdAccount {
  id: string
  name: string
  account_status: number
  currency: string
  timezone_name: string
  spend_cap: string
}

export interface MetaCampaign {
  id: string
  name: string
  status: string
  objective: string
  spend: string
  impressions: string
  clicks: string
  ctr: string
}

export interface ApiResponse<T> {
  success: boolean
  data: T
  cached?: boolean
  error?: string
}

class ClientSafeApiClient {
  private baseUrl = '/api'

  async getAdAccounts(): Promise<MetaAdAccount[]> {
    try {
      const response = await fetch(`${this.baseUrl}/meta/accounts/safe`)
      const result: ApiResponse<MetaAdAccount[]> = await response.json()

      if (!result.success) {
        throw new Error(result.error || 'Failed to fetch ad accounts')
      }

      return result.data
    } catch (error) {
      console.error('Error fetching ad accounts:', error)
      throw error
    }
  }

  async getCampaigns(accountId: string): Promise<MetaCampaign[]> {
    try {
      const response = await fetch(
        `${this.baseUrl}/meta/campaigns/safe?accountId=${encodeURIComponent(accountId)}`
      )
      const result: ApiResponse<MetaCampaign[]> = await response.json()

      if (!result.success) {
        throw new Error(result.error || 'Failed to fetch campaigns')
      }

      return result.data
    } catch (error) {
      console.error('Error fetching campaigns:', error)
      throw error
    }
  }

  async getInsights(accountId: string, dateRange?: string): Promise<any[]> {
    try {
      const params = new URLSearchParams({ accountId })
      if (dateRange) {
        params.append('dateRange', dateRange)
      }

      const response = await fetch(`${this.baseUrl}/meta/insights?${params}`)
      const result: ApiResponse<any[]> = await response.json()

      if (!result.success) {
        throw new Error(result.error || 'Failed to fetch insights')
      }

      return result.data
    } catch (error) {
      console.error('Error fetching insights:', error)
      throw error
    }
  }
}

export const clientSafeApi = new ClientSafeApiClient()