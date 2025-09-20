'use client'

import { useState } from 'react'

interface Task {
  id: string
  title: string
  label: string
  labelColor: string
  assignee: {
    name: string
    avatar: string
  }
}

interface Column {
  id: string
  title: string
  count: number
  tasks: Task[]
}

const columns: Column[] = [
  {
    id: 'todo',
    title: 'To Do',
    count: 3,
    tasks: [
      {
        id: '1',
        title: 'Design new ad creatives',
        label: 'Design',
        labelColor: 'text-blue-300 bg-blue-900',
        assignee: {
          name: 'Designer',
          avatar: 'https://lh3.googleusercontent.com/aida-public/AB6AXuBBo4G6uGh1__Qz4pYQKCHWQw-1h3GACXcvGMhU7-7De2t9fS0pTh9D4wk6PnJXQl4z0C7TBwRTyuUfW6iN1RuKjgfB8gF9CP2U_eYZYE8Yz8Md0uh7eBkSVeP_zo4Miq82DS1gLWceesP8hPGNwlUHPWmg1YR9dK9Uxa0um9T7PGaUhvXIaT6RoOKoubpPjeVLeEHSBVda0EFpbGcPDgeO918LJORwElFKHPL0uFfE1twKgtcSf7hvDmWMjlUDL9r3C1NJ4wPNbKo'
        }
      },
      {
        id: '2',
        title: 'Write copy for social media posts',
        label: 'Copywriting',
        labelColor: 'text-pink-300 bg-pink-900',
        assignee: {
          name: 'Copywriter',
          avatar: 'https://lh3.googleusercontent.com/aida-public/AB6AXuBpKRt22QA0PhBIrgArFvF4X-RGnG7VizA9TYFA4Iv9KbDu_iutarEHiDVcOXZi8XAP13Uy9tDs_BXa17uXgS_HYn3o11QG1sDQoey7i6uM5zTUcrhVjIild99VI6DiwnvhddbWiaLActVR6eOJTbwsRgXfmZgHDs7stlQAjpBW5j2RdOtKtRaQblud-1ahwTklSuxjO2ZnBiqkkeCmcsBAN8K-NNhwTpnbx1a7lK5lsaK4fDzBOq4HjP6KRZlgnoe4d0f3pzwQC6M'
        }
      },
      {
        id: '3',
        title: 'Setup new A/B test',
        label: 'Marketing',
        labelColor: 'text-indigo-300 bg-indigo-900',
        assignee: {
          name: 'Marketer',
          avatar: 'https://lh3.googleusercontent.com/aida-public/AB6AXuDuF7iAQfCoVogi3lSROqbK5VLzXTOIWPHvL6tG6rOh651Vvq9SeJSJtYxKSq22CrLYWs3PaRHz0JFcNvmxPmjHK10X26f62G8v-JzYrCsHH1IdrlVC9gmyDbQN4dDWJogipxjwaF-TEW3KHZSkEHvGohuCraNKrD-fzEXSRKf4jBS6pTlDvKqZNcUFBjrvsI8eHvgMZfgoVyCDb_mDCAmVXD582eMgieWe8IdFaV0e45w1_2mVPLfARnovANnNEOB_AuQkONQrEWY'
        }
      }
    ]
  },
  {
    id: 'in_progress',
    title: 'In Progress',
    count: 2,
    tasks: [
      {
        id: '4',
        title: 'Develop landing page',
        label: 'Development',
        labelColor: 'text-green-300 bg-green-900',
        assignee: {
          name: 'Developer',
          avatar: 'https://lh3.googleusercontent.com/aida-public/AB6AXuDbnj0k3kTEM80IBnG4MAtxp_YQ2ycr2ndu7eIAGlb_mPnUc22YigTsl0wv5a1Ky84RvMH2fCh9MAxeivUQPsZAIzeXpMyE9glV_2_y2wNUxt2rx_H_lxNfuV1_I6M5VQXnuwGez9sp0lK6OR44f7iqO0eWObaN6JstuNTknL_qVGj5lyXKztTkHqPITBiHOHEvlThizCeCFBKBSEdGM8SRPS0RKjELBMY-cUM7E_7HLiQWVlR4jRr2xhGXAgrrf7LqV8oL9l63z1w'
        }
      },
      {
        id: '5',
        title: 'Review campaign budget',
        label: 'Marketing',
        labelColor: 'text-indigo-300 bg-indigo-900',
        assignee: {
          name: 'Marketing Manager',
          avatar: 'https://lh3.googleusercontent.com/aida-public/AB6AXuBUKSM6ucEWwIpJICafU1_fR5bTz_qMmFOtlBI93Hvc_ZZ90FcNhXackx4tJDvghSH_o0vqo4xvcr6j-_9YXfqiMf4TMJhDhc9YCYTLL49tSHw8fFC9Wqb3-r1lnNz95ccLiL-ma7aMA5CFsO4mNoeXTniO9mAhWKAWcBuyOGM97dIvsa7pLaCD754znqsfLCpBZ-JV_rhzUwNFUWnAAsMSPyjuNtLXlSHQtBfaRzPtsZuO8A4vJOWfokTTgUD4773sZhyFew2-Sxs'
        }
      }
    ]
  },
  {
    id: 'review',
    title: 'In Review',
    count: 1,
    tasks: [
      {
        id: '6',
        title: 'Finalize ad targeting',
        label: 'Pending Approval',
        labelColor: 'text-yellow-300 bg-yellow-900',
        assignee: {
          name: 'Ad Specialist',
          avatar: 'https://lh3.googleusercontent.com/aida-public/AB6AXuAXhKfU2SMoNZUg3YjQsetqkFGcW0C-tkYP0puYlN3vy2y7M1swjg2USUiN8uKReFLjq_hnbag-q0u-NEuy3xZzT2x8AzOjCv2pbymnsTx7jmGV-erylcJe9n8aYEDnklT_MaXvHvqEGjYtZF1Iw_71B27Wsbg7Zh57QJ5mSEYG9xTaNsUohHaWJhTVavPUoGs2F9NZJ3D7sDd8T0MtV6oJPI44tLWkPrdZaX7WwpvDI8FVbgNz0u72h4K4mMYKQY4lAvBTwJsFRME'
        }
      }
    ]
  },
  {
    id: 'done',
    title: 'Done',
    count: 1,
    tasks: [
      {
        id: '7',
        title: 'Launch social media campaign',
        label: 'Completed',
        labelColor: 'text-gray-300 bg-gray-600',
        assignee: {
          name: 'Social Media Manager',
          avatar: 'https://lh3.googleusercontent.com/aida-public/AB6AXuDKFehu9HpUEt2aiduPj2eoDkZLErIauzNKwZgWRYZ4fEtMaZVo5TiBgV3kAVf7mfs6FlwHwJFyy3zMz3SakOks4j6b6ElPSSWgV6aRvMIg8y4sq2EugyyzErgoNbQ2VSJIZiwlLgXlGtW1AoGuwH8b4hKjIV71A-JLrGRXabmG526Fn_ywiBtly0UmhGbPOJvn5xKiI6SacVatsXZxbLGR12wg6RwrL_XPDkTpAgTXXi5MoAJrp6kqaW5eBrAJwmchFQnJWHUjy1Y'
        }
      }
    ]
  }
]

const teamMembers = [
  {
    id: '1',
    name: 'Team Member 1',
    avatar: 'https://lh3.googleusercontent.com/aida-public/AB6AXuDWt_5VUxYICzKl_sV_jgadZYHBwTn5Mf8XuYxZXmtBPgfsl1rVPPd-VIv9S-67MKCWK7DtsPtTyKEsaOJOEplplrWC89acXhc3G5Lu8uTNOv-BOZF9C5cLcDRRi7SyhubEv-xVQQETdFcs_6M93WGQI2R_0sLAIZWGwLPABZl3lPdRlpsLlwWVX8R8qh-UTkckgRtk1t9qlfZTUUdtGowhwD7xafDonBTq1vhqGhl03_uczH4H_Nv_443EXix_F7bH5ZoON4K25Wg'
  },
  {
    id: '2',
    name: 'Team Member 2',
    avatar: 'https://lh3.googleusercontent.com/aida-public/AB6AXuDndPaeDje37bhVOmBr_ycj6U8xcDng5oGem-wXXiDLFoOUF_qrDrsm48KWGfSI3dPsc61Mp0SAT7Bzjr2MQDs5dk441CUOOXzEvIm_uT1d3oCWYyBFAYOcvTGBdsJTM8nJ8JN-Ss7vZqqGpHY4J1MY3a3mrXz1fwfXtu-6mBru9kuX1GoS34DbkJdleaChw7MsKqQUzLYAj0-jvKGg3dNLYJWdCxyfBQ8I-6cI7ahJGuEV9QLVNGbzvoj-YRXZt-aDeX1VLT4hbjM'
  },
  {
    id: '3',
    name: 'Team Member 3',
    avatar: 'https://lh3.googleusercontent.com/aida-public/AB6AXuCa6eIGIFNqZHG4qSdA1CzaHiX4SyX7lALW5amZIwVJvOZ9r4JPNbqAuQLdc1V9aOAEkm8gUsgytoz9_68Vi7znRpFiZ0L6CV3GkqQxKOSI0B8VZ2yv1jx4Prrf9RsvpM5a2iAiczrCrRo_UGoc9I2QmmTPeHVPxv4JLpvUggJ0n-tA6BizXpE00JiEh552_z3wp1qyBlOy0RDA_TB8F-EoWsxBmgnFjvKjIjK-LAiOcnF65A2M2DqLakt4vYjGQxPcsSiNOBJElvA'
  }
]

export default function TeamBoardPage() {
  return (
    <div className="min-h-screen" style={{ backgroundColor: '#111827' }}>
      {/* Header */}
      <header className="flex items-center justify-between border-b px-10 py-3" style={{ borderColor: '#374151' }}>
        <nav className="flex items-center gap-8">
          <a href="#" className="text-gray-300 hover:text-white text-sm font-medium transition-colors">Campaigns</a>
          <a href="#" className="text-gray-300 hover:text-white text-sm font-medium transition-colors">Audiences</a>
          <a href="#" className="text-gray-300 hover:text-white text-sm font-medium transition-colors">Creatives</a>
          <a href="#" className="text-gray-300 hover:text-white text-sm font-medium transition-colors">Reports</a>
          <a href="#" className="text-gray-300 hover:text-white text-sm font-medium transition-colors">Experiments</a>
        </nav>
        <div className="flex items-center gap-4">
          <div className="flex -space-x-2 overflow-hidden">
            {teamMembers.map((member) => (
              <img
                key={member.id}
                alt="Team member avatar"
                className="inline-block size-8 rounded-full ring-2 ring-gray-800"
                src={member.avatar}
              />
            ))}
          </div>
          <button className="flex max-w-[480px] cursor-pointer items-center justify-center overflow-hidden rounded-md h-10 w-10 bg-gray-800 text-gray-300 hover:text-white hover:bg-gray-700 transition-colors">
            <span className="material-symbols-outlined text-xl">notifications</span>
          </button>
          <div
            className="bg-center bg-no-repeat aspect-square bg-cover rounded-full size-10"
            style={{ backgroundImage: 'url("https://lh3.googleusercontent.com/aida-public/AB6AXuCYkoXQPldSkwi9Q_CKReDg_MileWe7ljML_Fi6ApXXuokj-MMFj6CVECWZeF9KUhpCcH4F6Vdw8phEys_ERGzC57SofbDTj8cTzC0W9r0PNpcMNlSOkOO3oik-Jhy4wWpwgyiHBClGuRwSUcugcQ2AGohsFCUQ0oYdqgZqbwwsoTCsN87pau65Sy-S1zmSXkzXdThSlU9_HVPgDbjDWQilpeE8xD7LF7K6W_8h8nUMO92YDjhgGLQXc17EYC6F3oBO9YjXAhwPD60")' }}
          />
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 p-8">
        <div className="flex justify-between items-start mb-6">
          <div>
            <h1 className="text-white text-3xl font-bold">Summer Sale Campaign</h1>
            <p className="text-gray-400 mt-1">Manage your campaign progress and collaborate with your team</p>
          </div>
          <div className="flex items-center gap-2">
            <button className="flex items-center gap-2 text-sm font-medium text-gray-300 bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded-md transition-colors">
              <span className="material-symbols-outlined text-lg">filter_list</span>
              Filter
            </button>
            <button className="flex items-center gap-2 text-sm font-medium text-gray-300 bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded-md transition-colors">
              <span className="material-symbols-outlined text-lg">videocam</span>
              Start Call
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="border-b border-gray-800 mb-6">
          <nav aria-label="Tabs" className="-mb-px flex space-x-8">
            <a
              className="border-[var(--primary-color)] text-[var(--primary-color)] whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm"
              href="#"
            >
              Board
            </a>
            <a
              className="border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-500 whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm transition-colors"
              href="#"
            >
              List
            </a>
            <a
              className="border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-500 whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm transition-colors"
              href="#"
            >
              Calendar
            </a>
          </nav>
        </div>

        {/* Board Columns */}
        <div className="grid grid-cols-4 gap-6">
          {columns.map((column) => (
            <div key={column.id} className="bg-[#1F2937] rounded-lg p-4">
              <h3 className="text-white font-semibold mb-4 flex items-center justify-between">
                {column.title}
                <span className="text-gray-400 text-sm">{column.count}</span>
              </h3>
              <div className="space-y-4">
                {column.tasks.map((task) => (
                  <div
                    key={task.id}
                    className={`bg-gray-800 p-4 rounded-md shadow-sm cursor-grab ${
                      task.id === '7' ? 'opacity-70' : ''
                    }`}
                  >
                    <p className={`text-white font-medium text-sm ${
                      task.id === '7' ? 'line-through' : ''
                    }`}>
                      {task.title}
                    </p>
                    <div className="flex items-center justify-between mt-3">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${task.labelColor}`}>
                        {task.label}
                      </span>
                      <img
                        alt="Assignee avatar"
                        className="size-6 rounded-full"
                        src={task.assignee.avatar}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}