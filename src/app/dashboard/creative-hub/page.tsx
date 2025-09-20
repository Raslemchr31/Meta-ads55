'use client'

import { useState } from 'react'

export default function CreativeHubPage() {
  return (
    <div className="flex h-screen" style={{ backgroundColor: '#111111', fontFamily: 'Space Grotesk, sans-serif' }}>
      {/* Sidebar */}
      <aside className="w-64 bg-black p-6 flex flex-col justify-between">
        <div>
          <div className="flex items-center gap-2 mb-10">
            <div className="size-8 text-[#8013ec]">
              <svg fill="none" viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg">
                <path d="M39.5563 34.1455V13.8546C39.5563 15.708 36.8773 17.3437 32.7927 18.3189C30.2914 18.916 27.263 19.2655 24 19.2655C20.737 19.2655 17.7086 18.916 15.2073 18.3189C11.1227 17.3437 8.44365 15.708 8.44365 13.8546V34.1455C8.44365 35.9988 11.1227 37.6346 15.2073 38.6098C17.7086 39.2069 20.737 39.5564 24 39.5564C27.263 39.5564 30.2914 39.2069 32.7927 38.6098C36.8773 37.6346 39.5563 35.9988 39.5563 34.1455Z" fill="currentColor" />
                <path clipRule="evenodd" d="M10.4485 13.8519C10.4749 13.9271 10.6203 14.246 11.379 14.7361C12.298 15.3298 13.7492 15.9145 15.6717 16.3735C18.0007 16.9296 20.8712 17.2655 24 17.2655C27.1288 17.2655 29.9993 16.9296 32.3283 16.3735C34.2508 15.9145 35.702 15.3298 36.621 14.7361C37.3796 14.246 37.5251 13.9271 37.5515 13.8519C37.5287 13.7876 37.4333 13.5973 37.0635 13.2931C36.5266 12.8516 35.6288 12.3647 34.343 11.9175C31.79 11.0295 28.1333 10.4437 24 10.4437C19.8667 10.4437 16.2099 11.0295 13.657 11.9175C12.3712 12.3647 11.4734 12.8516 10.9365 13.2931C10.5667 13.5973 10.4713 13.7876 10.4485 13.8519ZM37.5563 18.7877C36.3176 19.3925 34.8502 19.8839 33.2571 20.2642C30.5836 20.9025 27.3973 21.2655 24 21.2655C20.6027 21.2655 17.4164 20.9025 14.7429 20.2642C13.1498 19.8839 11.6824 19.3925 10.4436 18.7877V34.1275C10.4515 34.1545 10.5427 34.4867 11.379 35.027C12.298 35.6207 13.7492 36.2054 15.6717 36.6644C18.0007 37.2205 20.8712 37.5564 24 37.5564C27.1288 37.5564 29.9993 37.2205 32.3283 36.6644C34.2508 36.2054 35.702 35.6207 36.621 35.027C37.4573 34.4867 37.5485 34.1546 37.5563 34.1275V18.7877ZM41.5563 13.8546V34.1455C41.5563 36.1078 40.158 37.5042 38.7915 38.3869C37.3498 39.3182 35.4192 40.0389 33.2571 40.5551C30.5836 41.1934 27.3973 41.5564 24 41.5564C20.6027 41.5564 17.4164 41.1934 14.7429 40.5551C12.5808 40.0389 10.6502 39.3182 9.20848 38.3869C7.84205 37.5042 6.44365 36.1078 6.44365 34.1455L6.44365 13.8546C6.44365 12.2684 7.37223 11.0454 8.39581 10.2036C9.43325 9.3505 10.8137 8.67141 12.343 8.13948C15.4203 7.06909 19.5418 6.44366 24 6.44366C28.4582 6.44366 32.5797 7.06909 35.657 8.13948C37.1863 8.67141 38.5667 9.3505 39.6042 10.2036C40.6278 11.0454 41.5563 12.2684 41.5563 13.8546Z" fill="currentColor" fillRule="evenodd" />
              </svg>
            </div>
            <h1 className="text-xl font-bold text-white">Ad Manager</h1>
          </div>
          <nav className="flex flex-col gap-4">
            <a className="text-sm font-medium text-white hover:text-[#8013ec] transition-colors" href="#">Campaigns</a>
            <a className="text-sm font-medium text-white hover:text-[#8013ec] transition-colors" href="#">Ad Sets</a>
            <a className="text-sm font-medium text-white hover:text-[#8013ec] transition-colors" href="#">Ads</a>
            <a className="text-sm font-medium text-white hover:text-[#8013ec] transition-colors" href="#">Audiences</a>
            <a className="text-sm font-bold text-[#8013ec] bg-white/10 p-2 rounded-md" href="#">Creative Library</a>
            <a className="text-sm font-medium text-white hover:text-[#8013ec] transition-colors" href="#">Reports</a>
          </nav>
        </div>
        <div className="flex items-center gap-3">
          <div className="bg-center bg-no-repeat aspect-square bg-cover rounded-full size-10" style={{backgroundImage: 'url("https://lh3.googleusercontent.com/aida-public/AB6AXuD4BZc-ZOkxYmjbCoYl1lFw_oftWYvX5MCroyVt07xjj72UnRb_GhqVHS7CI_391gbvtLPLFNnRhYPBl42_767GKC6a9ro1sE1xvPXZzVZcrO7bl9U21U-ycVVvDaByedAmELz291WkTA4Zz0u001fnvXOKYDJEI2OlrQdDVQE5qnoZen29XQsctxxGMfMJ6MNhzJABP_mWTqQn1bPKQzlacvEGWBvqsZpga8MmKShp1L3AgSW3zHHBcCCNo6jFfpcSOSIESDnrt6s")'}}></div>
          <div>
            <p className="font-bold text-white">John Doe</p>
            <p className="text-xs text-[#A0A0A0]">johndoe@email.com</p>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto">
        <div className="p-8">
          <div className="flex justify-between items-center mb-6">
            <div>
              <h2 className="text-3xl font-bold text-white">Creative Library</h2>
              <p className="text-[#A0A0A0]">Manage all your ad creative in one place</p>
            </div>
            <div className="flex items-center gap-4">
              <button className="flex items-center justify-center gap-2 h-10 px-4 rounded-md bg-[#1E1E1E] border border-[#333333] hover:bg-[#8013ec] transition-colors text-white">
                <span className="material-symbols-outlined text-lg">upload</span>
                Upload
              </button>
              <button className="flex items-center justify-center gap-2 h-10 px-4 rounded-md bg-[#8013ec] text-white font-bold hover:opacity-90 transition-opacity">
                <span className="material-symbols-outlined text-lg">sparkle</span>
                AI Generate
              </button>
            </div>
          </div>

          <div className="flex justify-between items-center mb-6 bg-[#1E1E1E] p-2 rounded-md border border-[#333333]">
            <div className="flex items-center gap-2">
              <button className="p-2 rounded-md bg-[#8013ec] text-white">
                <span className="material-symbols-outlined">grid_view</span>
              </button>
              <button className="p-2 rounded-md hover:bg-white/10 transition-colors text-white">
                <span className="material-symbols-outlined">list</span>
              </button>
              <div className="w-px h-6 bg-[#333333] mx-2"></div>
              <button className="p-2 rounded-md hover:bg-white/10 transition-colors text-white">
                <span className="material-symbols-outlined">filter_list</span>
              </button>
              <button className="p-2 rounded-md hover:bg-white/10 transition-colors text-white">
                <span className="material-symbols-outlined">check_box_outline_blank</span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-[repeat(auto-fill,minmax(250px,1fr))] gap-6">
            {Array.from({ length: 12 }, (_, i) => (
              <div key={i} className="group relative overflow-hidden rounded-lg cursor-pointer">
                <img alt="Ad Creative Thumbnail" className="w-full h-full object-cover aspect-[3/4] transition-transform duration-300 group-hover:scale-105" src="https://lh3.googleusercontent.com/aida-public/AB6AXuBPkG1u8Ka9WbN_FCqXcb1Yp7EwPC7_VAAEABW49-LTUzsXUdTnlL2rihkYc8s-uWWS8MBibKmNFcM8d-oiJ5bobiAGxiRGcbAN8H8nsHZF7A1Zqbqc5Uq-d2GRsERDO1__HPCxfjQcA2TvXEDvEr1zwEILB4P3PJWONsoqHT-5juGE2aMSeHRyGOlbXt3mHvGI91QYg4J6ZKgwd-IhOYuamzYZKFEmmzSP8vQn_PvFXVvhipZhV-8bYBwm075lkxzro8_oOl1CnN4"/>
                <div className="absolute inset-0 bg-black/20 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                  <span className="material-symbols-outlined text-5xl text-white">play_circle</span>
                </div>
                <div className="absolute top-2 right-2 bg-green-500 text-white text-xs font-bold px-2 py-1 rounded-full">92</div>
                <div className="absolute bottom-0 left-0 right-0 p-4 bg-gradient-to-t from-black/80 to-transparent">
                  <div className="flex justify-between items-center text-white text-sm">
                    <span>CTR: <strong>2.1%</strong></span>
                    <span>CPC: <strong>$0.45</strong></span>
                    <span>Imp: <strong>12k</strong></span>
                  </div>
                  <div className="flex gap-2 mt-3">
                    <button className="flex-1 text-xs bg-white/20 backdrop-blur-sm text-white py-1.5 rounded-md hover:bg-white/30 transition-colors">AI Variations</button>
                    <button className="bg-white/20 backdrop-blur-sm text-white p-1.5 rounded-md hover:bg-white/30 transition-colors">
                      <span className="material-symbols-outlined text-sm">more_horiz</span>
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="flex items-center justify-center mt-8 gap-2">
            <button className="flex size-8 items-center justify-center rounded-md hover:bg-white/10 transition-colors disabled:opacity-50 text-white" disabled>
              <span className="material-symbols-outlined">chevron_left</span>
            </button>
            <button className="flex size-8 items-center justify-center rounded-md bg-[#8013ec] text-white text-sm font-bold">1</button>
            <button className="flex size-8 items-center justify-center rounded-md hover:bg-white/10 text-sm font-medium text-[#A0A0A0] transition-colors">2</button>
            <button className="flex size-8 items-center justify-center rounded-md hover:bg-white/10 text-sm font-medium text-[#A0A0A0] transition-colors">3</button>
            <span className="text-[#A0A0A0]">...</span>
            <button className="flex size-8 items-center justify-center rounded-md hover:bg-white/10 text-sm font-medium text-[#A0A0A0] transition-colors">10</button>
            <button className="flex size-8 items-center justify-center rounded-md hover:bg-white/10 transition-colors text-white">
              <span className="material-symbols-outlined">chevron_right</span>
            </button>
          </div>
        </div>
      </main>

      {/* Right Sidebar */}
      <aside className="w-96 bg-[#1E1E1E] p-6 border-l border-[#333333] overflow-y-auto">
        <h3 className="text-xl font-bold mb-4 text-white">Creative Details</h3>
        <div className="relative mb-4">
          <img alt="" className="w-full rounded-lg aspect-[3/4] object-cover" src="https://lh3.googleusercontent.com/aida-public/AB6AXuBPczrPrhFIqWhX66Nej5FiLGImpAdYi5kfXVDAIJxSI9PRJL5nbgRVN4VZ1fCkpiZnxLm2T5EkxaOIPqqVhx2p1uo0bTwHB2C9qzpeBuwRauQP6GGiecg6KXKNpYgLu-6bh-n6-0bX8KitqFrOGb3Bh7oDpRy3RSHdgpt1H12LRfsK8uzc-1SNZ8mEIOr5q5JoQQw09YMet5MoGQkUrlD8AiAPQ037nKAuEzmiqTVnYzU5FBkVuM4zjj6SD_RAayHAjLj_t0aYzM0"/>
          <div className="absolute top-2 right-2 bg-green-500 text-white text-xs font-bold px-2 py-1 rounded-full flex items-center gap-1">
            <span className="material-symbols-outlined text-sm">star</span>
            92
          </div>
        </div>
        <h4 className="font-bold mb-2 text-white">Performance</h4>
        <div className="grid grid-cols-3 gap-2 mb-4">
          <div className="bg-black/20 p-3 rounded-md text-center">
            <p className="text-sm text-[#A0A0A0]">CTR</p>
            <p className="font-bold text-lg text-white">1.2%</p>
          </div>
          <div className="bg-black/20 p-3 rounded-md text-center">
            <p className="text-sm text-[#A0A0A0]">CPC</p>
            <p className="font-bold text-lg text-white">$0.50</p>
          </div>
          <div className="bg-black/20 p-3 rounded-md text-center">
            <p className="text-sm text-[#A0A0A0]">Impressions</p>
            <p className="font-bold text-lg text-white">10k</p>
          </div>
        </div>
        <h4 className="font-bold mb-2 text-white">Actions</h4>
        <button className="w-full flex items-center justify-center gap-2 h-10 px-4 rounded-md bg-[#8013ec] text-white font-bold hover:opacity-90 transition-opacity mb-2">
          <span className="material-symbols-outlined text-lg">auto_awesome</span>
          Generate Variations
        </button>
        <div className="grid grid-cols-4 gap-2">
          <button className="flex flex-col items-center gap-1 bg-black/20 p-3 rounded-md hover:bg-white/10 transition-colors text-white">
            <span className="material-symbols-outlined">edit</span>
            <span className="text-xs">Edit</span>
          </button>
          <button className="flex flex-col items-center gap-1 bg-black/20 p-3 rounded-md hover:bg-white/10 transition-colors text-white">
            <span className="material-symbols-outlined">content_copy</span>
            <span className="text-xs">Duplicate</span>
          </button>
          <button className="flex flex-col items-center gap-1 bg-black/20 p-3 rounded-md hover:bg-white/10 transition-colors text-white">
            <span className="material-symbols-outlined">archive</span>
            <span className="text-xs">Archive</span>
          </button>
          <button className="flex flex-col items-center gap-1 bg-black/20 p-3 rounded-md hover:bg-white/10 transition-colors text-white">
            <span className="material-symbols-outlined">delete</span>
            <span className="text-xs">Delete</span>
          </button>
        </div>
      </aside>
    </div>
  )
}