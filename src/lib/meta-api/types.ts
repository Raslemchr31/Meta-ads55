/**
 * Meta Graph API v23.0 Types
 * Comprehensive TypeScript interfaces for Meta Marketing API
 */

// Base API Response Types
export interface MetaAPIResponse<T = any> {
  data?: T
  paging?: {
    cursors: {
      before: string
      after: string
    }
    next?: string
    previous?: string
  }
  error?: MetaAPIError
}

export interface MetaAPIError {
  message: string
  type: string
  code: number
  error_subcode?: number
  error_user_title?: string
  error_user_msg?: string
  fbtrace_id: string
  is_transient?: boolean
}

// Rate Limiting Types
export interface RateLimitInfo {
  app_id_util_pct: number
  call_count: number
  total_cputime: number
  total_time: number
  type: string
  estimated_time_to_regain_access?: number
}

export interface RateLimitHeaders {
  'x-business-use-case-usage'?: string
  'x-app-usage'?: string
  'x-ad-account-usage'?: string
}

// Authentication & Access Token Types
export interface AccessTokenInfo {
  app_id: string
  type: string
  application: string
  data_access_expires_at: number
  expires_at: number
  is_valid: boolean
  scopes: string[]
  granular_scopes?: Array<{
    scope: string
    target_ids: string[]
  }>
  user_id?: string
}

export interface SystemUserToken {
  access_token: string
  token_type: 'bearer'
  expires_in?: number
  scope?: string
}

// Account & Business Types
export interface AdAccount {
  id: string
  account_id: string
  name: string
  account_status: number
  age_restrictions?: any
  amount_spent: string
  attribution_spec?: Array<{
    event_type: string
    window_days: number
  }>
  balance: string
  business?: {
    id: string
    name: string
  }
  business_city?: string
  business_country_code?: string
  business_name?: string
  business_state?: string
  business_street?: string
  business_street2?: string
  business_zip?: string
  capabilities: string[]
  created_time: string
  currency: string
  disable_reason?: number
  end_advertiser?: string
  end_advertiser_name?: string
  extended_credit_invoice_group?: any
  failed_delivery_checks?: Array<{
    check_name: string
    description: string
    summary: string
  }>
  fb_entity?: number
  funding_source?: string
  funding_source_details?: {
    id: string
    display_string: string
    type: number
  }
  has_migrated_permissions?: boolean
  has_page_authorized_adaccount?: boolean
  io_number?: string
  is_attribution_spec_system_default?: boolean
  is_direct_deals_enabled?: boolean
  is_in_3ds_authorization_enabled_market?: boolean
  is_notifications_enabled?: boolean
  is_personal?: number
  is_prepay_account?: boolean
  is_tax_id_required?: boolean
  liability_type?: string
  line_numbers?: number[]
  media_agency?: string
  min_campaign_group_spend_cap?: string
  min_daily_budget?: number
  owner?: string
  offsite_pixels_tos_accepted?: boolean
  partner?: string
  rf_spec?: any
  show_checkout_experience?: boolean
  spend_cap?: string
  tax_id?: string
  tax_id_status?: number
  tax_id_type?: string
  timezone_id?: number
  timezone_name?: string
  timezone_offset_hours_utc?: number
  tos_accepted?: any
  user_access_expire_time?: string
  user_tasks?: string[]
  user_tos_accepted?: any
  viewable_business?: any
}

// Campaign Types
export interface Campaign {
  id: string
  account_id: string
  adlabels?: AdLabel[]
  bid_strategy: string
  boosted_object_id?: string
  brand_lift_studies?: any[]
  budget_rebalance_flag?: boolean
  budget_remaining?: string
  buying_type?: string
  campaign_group_active_time?: string
  can_create_brand_lift_study?: boolean
  can_use_spend_cap?: boolean
  configured_status: string
  created_time: string
  daily_budget?: string
  effective_status: string
  issues_info?: Array<{
    error_code: number
    error_message: string
    error_summary: string
    error_type: string
    level: string
  }>
  last_budget_toggling_time?: string
  lifetime_budget?: string
  name: string
  objective: string
  pacing_type?: string[]
  promoted_object?: any
  recommendations?: any[]
  smart_promotion_type?: string
  source_campaign?: any
  source_campaign_id?: string
  special_ad_categories?: string[]
  special_ad_category?: string
  special_ad_category_country?: string[]
  spend_cap?: string
  start_time?: string
  status: string
  stop_time?: string
  topline_id?: string
  updated_time: string
}

// Ad Set Types
export interface AdSet {
  id: string
  account_id: string
  adlabels?: AdLabel[]
  adset_schedule?: Array<{
    start_minute: number
    end_minute: number
    days: number[]
  }>
  asset_feed_id?: string
  attribution_spec?: any[]
  bid_adjustments?: any
  bid_amount?: string
  bid_constraints?: any
  bid_info?: any
  bid_strategy: string
  billing_event: string
  budget_remaining?: string
  campaign?: Campaign
  campaign_id: string
  configured_status: string
  created_time: string
  creative_sequence?: string[]
  daily_budget?: string
  daily_min_spend_target?: string
  daily_spend_cap?: string
  destination_type?: string
  effective_status: string
  end_time?: string
  frequency_control_specs?: any[]
  full_funnel_exploration_mode?: string
  instagram_actor_id?: string
  is_dynamic_creative?: boolean
  issues_info?: Array<{
    error_code: number
    error_message: string
    error_summary: string
    error_type: string
    level: string
  }>
  learning_stage_info?: {
    attribution_windows?: string[]
    conversions?: number
    last_sig_edit_ts?: string
    status?: string
  }
  lifetime_budget?: string
  lifetime_imps?: number
  lifetime_min_spend_target?: string
  lifetime_spend_cap?: string
  multi_optimization_goal_weight?: string
  name: string
  optimization_goal: string
  optimization_sub_event?: string
  pacing_type?: string[]
  promoted_object?: any
  rf_prediction_id?: string
  source_adset?: any
  source_adset_id?: string
  start_time?: string
  status: string
  targeting?: TargetingSpec
  time_based_ad_rotation_id_blocks?: any[]
  time_based_ad_rotation_intervals?: any[]
  updated_time: string
  use_new_app_click?: boolean
}

// Ad Types
export interface Ad {
  id: string
  account_id: string
  ad_review_feedback?: any
  adlabels?: AdLabel[]
  adset?: AdSet
  adset_id: string
  bid_amount?: string
  bid_info?: any
  bid_type?: string
  campaign?: Campaign
  campaign_id: string
  configured_status: string
  conversion_domain?: string
  conversion_specs?: any[]
  created_time: string
  creative?: AdCreative
  demolink_hash?: string
  display_sequence?: number
  effective_status: string
  engagement_audience?: boolean
  failed_delivery_checks?: any[]
  issues_info?: Array<{
    error_code: number
    error_message: string
    error_summary: string
    error_type: string
    level: string
  }>
  last_updated_by_app_id?: string
  name: string
  preview_shareable_link?: string
  priority?: number
  recommendations?: any[]
  source_ad?: any
  source_ad_id?: string
  status: string
  tracking_specs?: any[]
  updated_time: string
}

// Creative Types
export interface AdCreative {
  id: string
  account_id: string
  actor_id?: string
  adlabels?: AdLabel[]
  applink_treatment?: string
  asset_feed_spec?: any
  authorization_category?: string
  auto_update?: boolean
  body?: string
  branded_content_sponsor_page_id?: string
  bundle_folder_id?: string
  call_to_action_type?: string
  categorization_criteria?: string
  category_media_source?: string
  collaborative_ads_lsb_image_bank_id?: string
  contextual_multi_ads?: any
  creative_sourcing_spec?: any
  degrees_of_freedom_spec?: any
  destination_set_id?: string
  dynamic_ad_voice?: string
  effective_authorization_category?: string
  effective_instagram_media_id?: string
  effective_instagram_story_id?: string
  effective_object_story_id?: string
  enable_direct_install?: boolean
  enable_launch_instant_app?: boolean
  image_crops?: any
  image_hash?: string
  image_url?: string
  instagram_actor_id?: string
  instagram_permalink_url?: string
  instagram_story_id?: string
  instagram_user_id?: string
  interactive_components_spec?: any
  link_deep_link_url?: string
  link_destination_display_url?: string
  link_og_id?: string
  link_url?: string
  messenger_sponsored_message?: string
  name: string
  object_id?: string
  object_store_url?: string
  object_story_id?: string
  object_story_spec?: ObjectStorySpec
  object_type?: string
  object_url?: string
  place_page_set_id?: string
  platform_customizations?: any
  playable_asset_id?: string
  portrait_customizations?: any
  product_set_id?: string
  recommender_settings?: any
  status: string
  template_url?: string
  template_url_spec?: any
  thumbnail_url?: string
  title?: string
  url_tags?: string
  use_page_actor_override?: boolean
  video_id?: string
}

// Targeting Types
export interface TargetingSpec {
  age_max?: number
  age_min?: number
  app_install_state?: string
  audience_network_positions?: string[]
  behavioral_targeting?: any[]
  brand_safety_content_filter_levels?: string[]
  catalog_based_targeting?: any
  connections?: any[]
  contextual_targeting_categories?: any[]
  countries?: string[]
  country?: string[]
  country_groups?: string[]
  custom_audiences?: Array<{
    id: string
    name?: string
  }>
  device_platforms?: string[]
  direct_install_devices?: boolean
  dynamic_audience_ids?: string[]
  education_majors?: any[]
  education_schools?: any[]
  education_statuses?: number[]
  effective_audience_network_positions?: string[]
  effective_device_platforms?: string[]
  effective_facebook_positions?: string[]
  effective_instagram_positions?: string[]
  effective_messenger_positions?: string[]
  effective_publisher_platforms?: string[]
  engagement_specs?: any[]
  ethnic_affinity?: any[]
  exclude_reached_since?: string[]
  excluded_connections?: any[]
  excluded_custom_audiences?: Array<{
    id: string
    name?: string
  }>
  excluded_geo_locations?: GeoLocation
  excluded_mobile_device_model?: string[]
  excluded_product_audience_specs?: any[]
  excluded_publisher_categories?: string[]
  excluded_publisher_list_ids?: string[]
  excluded_user_device?: string[]
  exclusions?: any
  facebook_positions?: string[]
  family_statuses?: number[]
  fb_deal_id?: string
  flexible_spec?: any[]
  friends_of_connections?: any[]
  genders?: number[]
  generation?: any[]
  geo_locations?: GeoLocation
  home_ownership?: any[]
  home_type?: any[]
  home_value?: any[]
  household_composition?: any[]
  income?: any[]
  industries?: any[]
  instagram_positions?: string[]
  interested_in?: number[]
  interests?: any[]
  is_whatsapp_destination_ad?: boolean
  keywords?: string[]
  life_events?: any[]
  locales?: string[]
  messenger_positions?: string[]
  moms?: any[]
  net_worth?: any[]
  office_type?: any[]
  place_page_set_ids?: string[]
  political_affinity?: any[]
  politics?: any[]
  product_audience_specs?: any[]
  prospecting_audience?: any
  publisher_platforms?: string[]
  radius?: number
  regions?: any[]
  relationship_statuses?: number[]
  site_category?: string[]
  targeting_optimization?: string
  user_adclusters?: any[]
  user_device?: string[]
  user_event?: any[]
  user_os?: string[]
  wireless_carrier?: string[]
  work_employers?: any[]
  work_positions?: any[]
  zips?: string[]
}

// Geo Location Types
export interface GeoLocation {
  countries?: string[]
  country_groups?: string[]
  regions?: Array<{
    key: string
    name?: string
  }>
  cities?: Array<{
    key: string
    radius: number
    distance_unit: string
    name?: string
  }>
  zips?: Array<{
    key: string
    name?: string
  }>
  places?: Array<{
    key: string
    name?: string
  }>
  custom_locations?: Array<{
    latitude: number
    longitude: number
    radius: number
    distance_unit: string
    address_string?: string
  }>
  geo_markets?: Array<{
    key: string
    name?: string
  }>
  electoral_districts?: Array<{
    key: string
    name?: string
  }>
  location_types?: string[]
}

// Object Story Spec Types
export interface ObjectStorySpec {
  page_id?: string
  instagram_actor_id?: string
  photo_data?: {
    image_hash?: string
    url?: string
    tagged_users?: string[]
    place_id?: string
  }
  video_data?: {
    video_id?: string
    image_hash?: string
    video_title?: string
    call_to_action?: any
    branded_content_sponsor_page_id?: string
    branded_content_guest_fb_page_id?: string
  }
  link_data?: {
    link?: string
    message?: string
    name?: string
    description?: string
    image_hash?: string
    call_to_action?: any
    branded_content_sponsor_page_id?: string
    branded_content_guest_fb_page_id?: string
    child_attachments?: any[]
    caption?: string
    additional_image_index?: number
  }
  template_data?: any
  text_data?: {
    message?: string
    link?: string
  }
}

// Insights Types
export interface InsightsFields {
  // Performance Metrics
  impressions?: string
  reach?: string
  frequency?: string
  clicks?: string
  unique_clicks?: string
  ctr?: string
  unique_ctr?: string
  cpc?: string
  cost_per_unique_click?: string
  cpm?: string
  cpp?: string
  spend?: string

  // Actions & Conversions
  actions?: Action[]
  action_values?: ActionValue[]
  conversions?: Conversion[]
  conversion_values?: ConversionValue[]
  cost_per_action_type?: CostPerActionType[]
  cost_per_conversion?: CostPerConversion[]

  // Video Metrics
  video_play_actions?: Action[]
  video_p25_watched_actions?: Action[]
  video_p50_watched_actions?: Action[]
  video_p75_watched_actions?: Action[]
  video_p100_watched_actions?: Action[]
  video_avg_time_watched_actions?: Action[]
  video_complete_watched_actions?: Action[]

  // Engagement Metrics
  post_engagements?: string
  page_engagements?: string
  likes?: string
  comments?: string
  shares?: string
  follows?: string

  // Attribution & Quality
  quality_score?: QualityScore
  purchase_roas?: PurchaseROAS[]

  // Date & Metadata
  date_start?: string
  date_stop?: string
  account_id?: string
  account_name?: string
  campaign_id?: string
  campaign_name?: string
  adset_id?: string
  adset_name?: string
  ad_id?: string
  ad_name?: string
}

export interface Action {
  action_type: string
  value: string
  '1d_click'?: string
  '7d_click'?: string
  '28d_click'?: string
  '1d_view'?: string
  '7d_view'?: string
  '28d_view'?: string
  dda?: string
}

export interface ActionValue {
  action_type: string
  value: string
  '1d_click'?: string
  '7d_click'?: string
  '28d_click'?: string
  '1d_view'?: string
  '7d_view'?: string
  '28d_view'?: string
}

export interface Conversion {
  action_type: string
  value: string
}

export interface ConversionValue {
  action_type: string
  value: string
}

export interface CostPerActionType {
  action_type: string
  value: string
}

export interface CostPerConversion {
  action_type: string
  value: string
}

export interface QualityScore {
  quality_score: number
  engagement_rate_ranking?: string
  conversion_rate_ranking?: string
  quality_ranking?: string
}

export interface PurchaseROAS {
  action_type: string
  value: string
}

// Webhook Types
export interface WebhookData {
  object: string
  entry: WebhookEntry[]
}

export interface WebhookEntry {
  id: string
  time: number
  changes?: WebhookChange[]
}

export interface WebhookChange {
  field: string
  value: any
}

// Batch Request Types
export interface BatchRequest {
  method: string
  relative_url: string
  body?: string
  name?: string
  omit_response_on_success?: boolean
  depends_on?: string
  headers?: Record<string, string>
}

export interface BatchResponse {
  code: number
  headers?: Array<{ name: string; value: string }>
  body: string
}

// Label Types
export interface AdLabel {
  id: string
  name: string
  created_time?: string
  updated_time?: string
}

// Error Recovery Types
export interface RetryConfig {
  maxRetries: number
  baseDelayMs: number
  maxDelayMs: number
  backoffMultiplier: number
  retryableStatusCodes: number[]
  retryableErrorCodes: number[]
}

export interface CircuitBreakerConfig {
  failureThreshold: number
  resetTimeoutMs: number
  monitoringPeriodMs: number
}

// Queue Management Types
export interface QueuedRequest {
  id: string
  method: string
  endpoint: string
  data?: any
  priority: number
  retryCount: number
  scheduledAt: Date
  maxRetries: number
  onSuccess?: (result: any) => void
  onFailure?: (error: any) => void
}

export interface QueueStats {
  pending: number
  processing: number
  completed: number
  failed: number
  rateLimited: number
}

// Performance Monitoring Types
export interface APIMetrics {
  endpoint: string
  method: string
  responseTime: number
  statusCode: number
  timestamp: Date
  userId?: string
  accountId?: string
  errorType?: string
  rateLimitInfo?: RateLimitInfo
}

export interface SystemHealth {
  api: {
    healthy: boolean
    latency: number
    errorRate: number
  }
  cache: {
    healthy: boolean
    hitRate: number
    memory: string
  }
  database: {
    healthy: boolean
    connectionPool: number
    queryTime: number
  }
  queue: {
    healthy: boolean
    pending: number
    processing: number
  }
}

// Attribution Engine Types
export interface AttributionEvent {
  eventType: string
  timestamp: Date
  userId?: string
  sessionId?: string
  adId?: string
  campaignId?: string
  adsetId?: string
  accountId: string
  value?: number
  currency?: string
  customData?: Record<string, any>
  sourceIp?: string
  userAgent?: string
  referrer?: string
  fbp?: string  // Facebook browser ID
  fbc?: string  // Facebook click ID
}

export interface AttributionModel {
  name: string
  windowDays: number
  viewThroughDays: number
  clickThroughDays: number
  includeCrossDevice: boolean
  includeViewThrough: boolean
}

export interface AttributionResult {
  eventId: string
  attributedTouchpoints: Array<{
    adId: string
    campaignId: string
    adsetId: string
    timestamp: Date
    touchpointType: 'click' | 'view'
    attribution_credit: number
  }>
  totalValue: number
  currency?: string
  modelUsed: string
}