'use client'

import { useState } from 'react'

export default function AnalyticsPage() {
  return (
    <div className="min-h-screen" style={{ backgroundColor: '#111827' }}>
      {/* Fixed Header with Live Metrics */}
      <div className="fixed top-0 left-0 w-full z-20 bg-[#111827]/80 backdrop-blur-md">
        <header className="flex items-center justify-between whitespace-nowrap border-b border-solid border-b-[#374151] px-10 py-4">
          <div className="flex items-center gap-4 text-white">
            <svg className="h-8 w-8 text-[#7F13EC]" fill="none" viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg">
              <g clipPath="url(#clip0_6_319)">
                <path d="M8.57829 8.57829C5.52816 11.6284 3.451 15.5145 2.60947 19.7452C1.76794 23.9758 2.19984 28.361 3.85056 32.3462C5.50128 36.3314 8.29667 39.7376 11.8832 42.134C15.4698 44.5305 19.6865 45.8096 24 45.8096C28.3135 45.8096 32.5302 44.5305 36.1168 42.134C39.7033 39.7375 42.4987 36.3314 44.1494 32.3462C45.8002 28.361 46.2321 23.9758 45.3905 19.7452C44.549 15.5145 42.4718 11.6284 39.4217 8.57829L24 24L8.57829 8.57829Z" fill="currentColor"></path>
              </g>
              <defs>
                <clipPath id="clip0_6_319">
                  <rect fill="white" height="48" width="48"></rect>
                </clipPath>
              </defs>
            </svg>
            <h2 className="text-white text-xl font-bold leading-tight tracking-[-0.015em]">AdPlatform</h2>
          </div>
          <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-gray-300">
            <a className="hover:text-white transition-colors" href="#">Campaigns</a>
            <a className="hover:text-white transition-colors" href="#">Audiences</a>
            <a className="hover:text-white transition-colors" href="#">Creative Library</a>
            <a className="hover:text-white transition-colors" href="#">Events Manager</a>
            <a className="text-white font-bold" href="#">Reports</a>
          </nav>
          <div className="flex items-center gap-4">
            <button className="flex h-10 w-10 cursor-pointer items-center justify-center overflow-hidden rounded-full bg-[#1F2937] text-gray-300 hover:text-white transition-colors">
              <span className="material-symbols-outlined"> help </span>
            </button>
            <div className="bg-center bg-no-repeat aspect-square bg-cover rounded-full size-10" style={{backgroundImage: 'url("https://lh3.googleusercontent.com/aida-public/AB6AXuAzyhqrAXnsJb1T3RocTp-N-52iRk3Ji66st75V1OsVNAYdP6ATudty3HKkOjPAWVPcN27Jc3wokWJCkgg1AoZwPSLQsTLENQAh_tBFd2SZArDGTTYgQ0V8OnidllIeYLLqu9WAA7B7NQQXPoEZad-ze_uHxE6dbZJTblnrPRq_komfBdqw4tTRfBi_rOPIyYsLsW9bEOGgYux_TqpdR9JB1Jq6N7-7WmxxPskuaq3-jZFKB-ZtHKvjZZlOC7GL-8w_u4WSYA1OF9g")'}}></div>
          </div>
        </header>
        <div className="w-full bg-black/20 text-white text-sm font-mono p-2 flex items-center justify-center gap-8 overflow-x-auto whitespace-nowrap">
          <p className="text-gray-400">Live Campaign Metrics:</p>
          <span className="flex items-center gap-2">
            <span className="text-[#00FF00]">Impressions:</span> 123,456 <span className="text-green-500 text-xs">▲</span>
          </span>
          <span className="flex items-center gap-2">
            <span className="text-[#00FF00]">Clicks:</span> 1,234 <span className="text-green-500 text-xs">▲</span>
          </span>
          <span className="flex items-center gap-2">
            <span className="text-[#00FF00]">Conversions:</span> 123 <span className="text-red-500 text-xs">▼</span>
          </span>
        </div>
      </div>

      {/* Main Content */}
      <main className="flex-1 px-4 sm:px-6 lg:px-8 py-8 pt-40">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8">
            <div className="flex-1">
              <h1 className="text-4xl font-bold text-white tracking-tight">Analytics Dashboard</h1>
              <p className="text-gray-400 mt-2">Analyze your campaign performance with detailed metrics and visualizations.</p>
            </div>
            <div className="flex items-center gap-4 mt-4 md:mt-0">
              <div className="flex items-center gap-2">
                <input className="form-input flex w-full min-w-0 flex-1 resize-none overflow-hidden rounded-md text-white focus:outline-0 focus:ring-0 border border-[#374151] bg-[#1F2937] focus:border-[#7F13EC] h-10 placeholder:text-gray-400 px-3 text-sm" type="date" defaultValue="2024-03-01"/>
                <span className="text-gray-400">to</span>
                <input className="form-input flex w-full min-w-0 flex-1 resize-none overflow-hidden rounded-md text-white focus:outline-0 focus:ring-0 border border-[#374151] bg-[#1F2937] focus:border-[#7F13EC] h-10 placeholder:text-gray-400 px-3 text-sm" type="date" defaultValue="2024-03-28"/>
              </div>
              <div className="flex items-center gap-2">
                <label className="text-sm text-gray-400" htmlFor="compare-toggle">Compare</label>
                <button className="relative inline-flex h-6 w-11 items-center rounded-full bg-[#374151] transition-colors focus:outline-none focus:ring-2 focus:ring-[#7F13EC] focus:ring-offset-2 focus:ring-offset-[#111827]" id="compare-toggle">
                  <span className="inline-block h-4 w-4 transform rounded-full bg-white transition-transform translate-x-1"></span>
                </button>
              </div>
            </div>
          </div>

          {/* KPI Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div className="bg-[#1F2937] rounded-lg p-6 flex flex-col justify-between border border-transparent hover:border-[#7F13EC] transition-all duration-300 transform hover:-translate-y-1">
              <div>
                <div className="flex justify-between items-start">
                  <p className="text-sm font-medium text-gray-400">Impressions</p>
                  <p className="text-sm font-medium text-green-400">+15%</p>
                </div>
                <p className="text-3xl font-bold text-white mt-2">12,345,678</p>
              </div>
              <div className="h-20 mt-4 -mb-2 -mx-2">
                <div className="w-full h-full bg-center bg-no-repeat bg-contain" style={{backgroundImage: 'url("https://lh3.googleusercontent.com/aida-public/AB6AXuDFjPNTWUlZBNisMjymgRamkGSmKCXWPgPzKSTK_aMyChHHD0iNFIzbsD-dC_KwiJkYnN4K8mhDQ8O1K8sIP-DNVYcl-1Cvnb5C_XQBKPEAAN9iOxBWOrWShYdR9FI78RLTktknHjtzzW1qIo9i5VDoCmAcuEwDGXyV7vGWH1jPysoaqWsN1-755HeAfKIRFB2BomOfsaZ7vy1Xm57PCtGFtDtaIRnoYnhPt2ac5oPM44TspPvUs0rFBESpWORa4WtZyv_cT76MJ2c")'}}></div>
              </div>
            </div>
            <div className="bg-[#1F2937] rounded-lg p-6 flex flex-col justify-between border border-transparent hover:border-[#7F13EC] transition-all duration-300 transform hover:-translate-y-1">
              <div>
                <div className="flex justify-between items-start">
                  <p className="text-sm font-medium text-gray-400">Reach</p>
                  <p className="text-sm font-medium text-green-400">+12%</p>
                </div>
                <p className="text-3xl font-bold text-white mt-2">8,765,432</p>
              </div>
              <div className="h-20 mt-4 -mb-2 -mx-2">
                <div className="w-full h-full bg-center bg-no-repeat bg-contain" style={{backgroundImage: 'url("https://lh3.googleusercontent.com/aida-public/AB6AXuBOWe7GNL6gY2-TAWqpBXtej-2AGifLXlYmmHR00t5Iw7I8BLFvHUiP9oujUbBrRu_7IO0aN7ygEZCHg7LufjElND9n4fs7-ucC4fdYcs2aRshoQHsa_duWNHVCnhRLa87_5H-g0Hn1rwkNBnu_x17bqyQ3iSLEwEwZA4Ved-XPvfEQ_xBhkeoawe-3IGt1XFdRdOUzC0-gTtoTlxEPGKIFYa6HA9pBP3L-hWr47pC7On1cze7UyBEoPcLRmNfnWNPqU0HzpXxfHmE")'}}></div>
              </div>
            </div>
            <div className="bg-[#1F2937] rounded-lg p-6 flex flex-col justify-between border border-transparent hover:border-[#7F13EC] transition-all duration-300 transform hover:-translate-y-1">
              <div>
                <div className="flex justify-between items-start">
                  <p className="text-sm font-medium text-gray-400">Clicks</p>
                  <p className="text-sm font-medium text-green-400">+10%</p>
                </div>
                <p className="text-3xl font-bold text-white mt-2">543,210</p>
              </div>
              <div className="h-20 mt-4 -mb-2 -mx-2">
                <div className="w-full h-full bg-center bg-no-repeat bg-contain" style={{backgroundImage: 'url("https://lh3.googleusercontent.com/aida-public/AB6AXuCMhJZMWahLiNXtZVs8N5tRgOFs8dyHL0KHZcN8tjpYxU-Ss5zTmlk0f1f4NKlZlySAI1FSjaCVKXc6MuL1zwuaHt4ywo4RTfF816I2ys3AXD77g1f7QC9TryOMvvEd7UPQ6Qha9gkbn3cpcfK7BpqoyUVgng36XgpNksfUunaA7d7r7xxL72wAdlnWDOjalueJQhI3ees8CKzQOaypOr988FyyGTSv93-we_Jkwg9PGz7VK3AWqicy1Ia_qxcnZdLD0P88YL48jC0")'}}></div>
              </div>
            </div>
            <div className="bg-[#1F2937] rounded-lg p-6 flex flex-col justify-between border border-transparent hover:border-[#7F13EC] transition-all duration-300 transform hover:-translate-y-1">
              <div>
                <div className="flex justify-between items-start">
                  <p className="text-sm font-medium text-gray-400">Conversions</p>
                  <p className="text-sm font-medium text-green-400">+8%</p>
                </div>
                <p className="text-3xl font-bold text-white mt-2">12,345</p>
              </div>
              <div className="h-20 mt-4 -mb-2 -mx-2">
                <div className="w-full h-full bg-center bg-no-repeat bg-contain" style={{backgroundImage: 'url("https://lh3.googleusercontent.com/aida-public/AB6AXuC7f_4dY2_fN0rcaVxkmCN7gmFsSoPB4u7kSJMrFzS6Ao19-V4nlwXAYdB3wTNlUrjknxdBvbtT1hTcVD20XGZQkoGzZNfN914_hb-moEz9iAkImTp_O-9DC6eVbwsI4C82tWwjaC6VNTcz-lim8djEuGRl0ZJIvfGxUru9iuneMVgj7pOTSAYq8hn3Als3GYCGymJCwO4unCKkYQ_6hEeNY7kaO5auYFxmCOkz71qrecJ4uahuONuLmN_VAqi_RDXY1mSQ4Zr4h0E")'}}></div>
              </div>
            </div>
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
            <div className="bg-[#1F2937] p-6 rounded-lg">
              <h2 className="text-xl font-bold text-white mb-4">Conversion Funnel</h2>
              <div className="w-full aspect-video rounded-md overflow-hidden">
                <div className="w-full h-full bg-center bg-no-repeat bg-cover" style={{backgroundImage: 'url("https://lh3.googleusercontent.com/aida-public/AB6AXuBoV2qbschEpbZWwIz4MT_7E_Np4xnfde2ybWpw2FiYTe0J-HOZdYZ1AVC5hRXbbNybIcv6dX4tXD-pEoIiHhLQq3_pM8un447v8fWxW8zzpCcGMGoYMhpQ3GXrOKQh0encb8_FcCW6UQON_IUJvfxbIqyV8ilPvszh_OZSoOTrQ4osdgL93sXs7dk19rHc751cF42vLt13h14Yx55CkDfUxsXzlbHcqMIhtKk1hEUHOt2UbN18lYe-bUAmfJQZckbE0G0UPDs-7sg")'}}></div>
              </div>
            </div>
            <div className="bg-[#1F2937] p-6 rounded-lg">
              <h2 className="text-xl font-bold text-white mb-4">Performance Heatmap</h2>
              <div className="w-full aspect-video rounded-md overflow-hidden">
                <div className="w-full h-full bg-center bg-no-repeat bg-cover" style={{backgroundImage: 'url("https://lh3.googleusercontent.com/aida-public/AB6AXuCfCFITubXqTgBV5h7LqoQgFLy26HcUoQTQE3nFs_FXQIx40DAtIx6Ohkf5wYVZcE1Xqzt-EJ99u-wUn87voUCmA9xqVlVllq5oXzzK2TQ-IBHcnRptcW4KpTiyDH8LlkCDqrtVXdoo3MtmvRx2inizTKYoEbj4mOVtPAsILIqWwYIoA8JvnXT7j-eni2z7RKHV9T4lB_m7is6UBbXMSCU-D9WzkNHZhqqCdkMYoYQNQBNME5il90sul0F4K0k0T5FnZTSq6eXmxDI")'}}></div>
              </div>
            </div>
          </div>

          {/* Cohort Analysis Table */}
          <div className="bg-[#1F2937] p-6 rounded-lg mb-8">
            <h2 className="text-xl font-bold text-white mb-4">Cohort Analysis</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-gray-400">
                <thead className="text-xs text-gray-300 uppercase bg-[#374151]/50">
                  <tr>
                    <th className="px-6 py-3 rounded-l-lg" scope="col">Cohort</th>
                    <th className="px-6 py-3 text-center" scope="col">Day 0</th>
                    <th className="px-6 py-3 text-center" scope="col">Day 1</th>
                    <th className="px-6 py-3 text-center" scope="col">Day 2</th>
                    <th className="px-6 py-3 text-center" scope="col">Day 3</th>
                    <th className="px-6 py-3 text-center" scope="col">Day 4</th>
                    <th className="px-6 py-3 text-center" scope="col">Day 5</th>
                    <th className="px-6 py-3 text-center" scope="col">Day 6</th>
                    <th className="px-6 py-3 text-center rounded-r-lg" scope="col">Day 7</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className="border-b border-[#374151]">
                    <th className="px-6 py-4 font-medium text-white whitespace-nowrap" scope="row">Week of Jan 1</th>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/50 text-teal-300 p-2 rounded-md">100%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/30 text-teal-400 p-2 rounded-md">20%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/20 text-teal-500 p-2 rounded-md">15%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/20 text-teal-500 p-2 rounded-md">12%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/10 text-teal-600 p-2 rounded-md">10%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/10 text-teal-600 p-2 rounded-md">8%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-black/20 text-gray-500 p-2 rounded-md">7%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-black/20 text-gray-500 p-2 rounded-md">6%</span></td>
                  </tr>
                  <tr className="border-b border-[#374151]">
                    <th className="px-6 py-4 font-medium text-white whitespace-nowrap" scope="row">Week of Jan 8</th>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/50 text-teal-300 p-2 rounded-md">100%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/30 text-teal-400 p-2 rounded-md">22%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/20 text-teal-500 p-2 rounded-md">18%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/20 text-teal-500 p-2 rounded-md">15%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/20 text-teal-500 p-2 rounded-md">12%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/10 text-teal-600 p-2 rounded-md">10%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/10 text-teal-600 p-2 rounded-md">9%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/10 text-teal-600 p-2 rounded-md">8%</span></td>
                  </tr>
                  <tr className="border-b border-[#374151]">
                    <th className="px-6 py-4 font-medium text-white whitespace-nowrap" scope="row">Week of Jan 15</th>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/50 text-teal-300 p-2 rounded-md">100%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/40 text-teal-300 p-2 rounded-md">25%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/30 text-teal-400 p-2 rounded-md">20%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/20 text-teal-500 p-2 rounded-md">18%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/20 text-teal-500 p-2 rounded-md">15%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/20 text-teal-500 p-2 rounded-md">12%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/10 text-teal-600 p-2 rounded-md">11%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/10 text-teal-600 p-2 rounded-md">10%</span></td>
                  </tr>
                  <tr className="border-b border-[#374151]">
                    <th className="px-6 py-4 font-medium text-white whitespace-nowrap" scope="row">Week of Jan 22</th>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/50 text-teal-300 p-2 rounded-md">100%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/40 text-teal-300 p-2 rounded-md">28%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/30 text-teal-400 p-2 rounded-md">23%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/30 text-teal-400 p-2 rounded-md">20%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/20 text-teal-500 p-2 rounded-md">18%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/20 text-teal-500 p-2 rounded-md">15%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/20 text-teal-500 p-2 rounded-md">13%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/20 text-teal-500 p-2 rounded-md">12%</span></td>
                  </tr>
                  <tr>
                    <th className="px-6 py-4 font-medium text-white whitespace-nowrap" scope="row">Week of Jan 29</th>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/50 text-teal-300 p-2 rounded-md">100%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/40 text-teal-300 p-2 rounded-md">30%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/40 text-teal-300 p-2 rounded-md">25%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/30 text-teal-400 p-2 rounded-md">22%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/30 text-teal-400 p-2 rounded-md">20%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/20 text-teal-500 p-2 rounded-md">18%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/20 text-teal-500 p-2 rounded-md">15%</span></td>
                    <td className="px-6 py-4 text-center"><span className="bg-teal-900/20 text-teal-500 p-2 rounded-md">14%</span></td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Export & Scheduled Reports */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="bg-[#1F2937] p-6 rounded-lg">
              <h2 className="text-xl font-bold text-white mb-4">Export Reports</h2>
              <form className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1" htmlFor="report-name">Report Name</label>
                  <input className="form-input flex w-full min-w-0 flex-1 resize-none overflow-hidden rounded-md text-white focus:outline-0 focus:ring-2 focus:ring-[#7F13EC] border border-[#374151] bg-[#111827] h-12 placeholder:text-gray-500 px-4 text-sm" id="report-name" placeholder="e.g. Q1 Performance" type="text"/>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1" htmlFor="file-format">File Format</label>
                  <select className="form-select flex w-full min-w-0 flex-1 resize-none overflow-hidden rounded-md text-white focus:outline-0 focus:ring-2 focus:ring-[#7F13EC] border border-[#374151] bg-[#111827] h-12 placeholder:text-gray-500 px-4 text-sm" id="file-format">
                    <option>CSV</option>
                    <option>XLSX</option>
                    <option>PDF</option>
                  </select>
                </div>
                <button className="flex w-full items-center justify-center rounded-md h-12 px-4 bg-[#7F13EC] text-white text-sm font-bold tracking-wide hover:bg-[#6c11ce] transition-colors" type="submit">
                  <span className="material-symbols-outlined mr-2"> download </span>
                  Export Now
                </button>
              </form>
            </div>
            <div className="bg-[#1F2937] p-6 rounded-lg">
              <h2 className="text-xl font-bold text-white mb-4">Scheduled Reports</h2>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-[#111827] rounded-md">
                  <div>
                    <p className="font-semibold text-white">Campaign Performance</p>
                    <p className="text-sm text-gray-400">Weekly, next: Feb 29, 2024</p>
                  </div>
                  <button className="text-gray-400 hover:text-white">
                    <span className="material-symbols-outlined"> more_vert </span>
                  </button>
                </div>
                <div className="flex items-center justify-between p-4 bg-[#111827] rounded-md">
                  <div>
                    <p className="font-semibold text-white">Audience Engagement</p>
                    <p className="text-sm text-gray-400">Monthly, next: Mar 1, 2024</p>
                  </div>
                  <button className="text-gray-400 hover:text-white">
                    <span className="material-symbols-outlined"> more_vert </span>
                  </button>
                </div>
                <button className="flex w-full items-center justify-center rounded-md h-12 px-4 border-2 border-dashed border-[#374151] text-gray-300 text-sm font-bold tracking-wide hover:bg-[#374151] hover:text-white transition-colors">
                  <span className="material-symbols-outlined mr-2"> add </span>
                  Schedule New Report
                </button>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}