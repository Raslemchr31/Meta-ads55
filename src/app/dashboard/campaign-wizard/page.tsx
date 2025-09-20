'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'

const objectives = [
  {
    id: 'brand-awareness',
    title: 'Brand Awareness',
    description: 'Show your ads to people who are most likely to be interested in your brand.',
    image: 'https://lh3.googleusercontent.com/aida-public/AB6AXuC6iP2fLtwkOCgBt1k1Akk64bugri79XAeYVFZ_ElvlUcYcC07bhPouFtfWz-SNYb7j7y3fuScZG01maJ4Pdz-D8D-QgtiJ-UmOeqYR4SsLKUXsX7JRQf33f_NqbQRUzcfYa8OfNxHr-MRvIS2Zk6Bogk7EMjlO33y-3DFwLSc2MrommqzTl5CgP-fjTOxHe26xhYGEtbFPjSL4lnc1F6Zr4Ka06YOTtxXy5WiF0zhz9OXYyz1xgxXB36lNUCGiDGqN_3cSdbk0HJs'
  },
  {
    id: 'reach',
    title: 'Reach',
    description: 'Maximize the number of people who see your ads.',
    image: 'https://lh3.googleusercontent.com/aida-public/AB6AXuBCYZQ-spFg50uN58Jr7HC32fM8iRd_i0Vy3aEo8jeajVBu6Niw6MGusXhPCP97541duDe5e0XVs1J-dStBk-oh2U7EFTCprKmSWBmZQbtoLAW5YXRr1V7HJmuU_wLClFXMoig4XQjRKUWKvgBFXfMFf1Ms1YRhBko7jmN-3ycqYXS4Toa1z_KbEH_OHrmpyH0qRZUWYExBtAzIzyTtij6xhjz9gzBjRkRMFYQMV0f6hXvampgCMJzsonjFWlSis6opnLSdA57SK_E'
  },
  {
    id: 'traffic',
    title: 'Traffic',
    description: 'Drive people to your website or app.',
    image: 'https://lh3.googleusercontent.com/aida-public/AB6AXuA5kcarL1F18IY5QJzLLX_ai5ub18Fzw7Ion8Gm5rmV30-TQ39TfX88gjFfa9wY-CgZJCPsftgLt6j2JfwCrTkA8nk2v6ot3bKOoNplodqZSIBdeed4F_Amro7oWY6NI16BA5W6FgGzbDHbzehrDVyNnAaMZ5Tna-QslZE8EDZf7oq6Owbx4DLRbjpYFO2ujNmGBSMcqM82hcRcA3yRU_r4IiIgtAmVZ-pSxIBqmw-4xiVqpYC_aDlDJi_7U9H5UAKoZzoztFASgC8'
  },
  {
    id: 'engagement',
    title: 'Engagement',
    description: 'Get more people to interact with your posts or Page.',
    image: 'https://lh3.googleusercontent.com/aida-public/AB6AXuBR9_c0iPsta3l1t75oL6knzwfBtRdKAP4qo23jX0UE1LIMYR40yq0tImKxJCWryuIYJxAJM6HlRFK3KPpzPgMS-t8vw5SkFvCgR5LpLxePcPf1vXrZOKSx8nldgE_K8YIF_8d-ou9vYRXUXj1mAtqNfcjJZcOZTJ7TTAQBUOd3eWI5c56HgZJE1muXsH3s1n4ehgyJfgk60Fg6uud-3Q9tLixPUlbPPq57JXWHmVWMK2ZXbT0BXOYcjcztAYyu2KHK0hYliO-uh44'
  },
  {
    id: 'app-installs',
    title: 'App Installs',
    description: 'Get more people to install your app.',
    image: 'https://lh3.googleusercontent.com/aida-public/AB6AXuCNfODhPc_8gv78DYrpKz3npWRWKazO0RHP0W_MIIf8AsstWu7-YqeroNE4KMfK4j_sRZ8jgWoLgbkituvat8gKM9vIYm9i63lqB-hExWenv5pPQkgU2Cn4T3dq2Omw5QgQwOElu03arHP3KPCog-9jXiOZbl6BhY8f3CSFgSSDzVGBr2xxExfuFIKpjrWSFX8iwEFbigVVDYrPXzlladJNsA8X8_jcUb_D--VI6bC15XlmVaTADBq4TrgsfroUmpJiMNIl8jl2X3c'
  },
  {
    id: 'video-views',
    title: 'Video Views',
    description: 'Get more people to watch your videos.',
    image: 'https://lh3.googleusercontent.com/aida-public/AB6AXuAHWFNwyCt6ZzxS4SrGRGcB5rbLozRv6UxCrlF5Q-XWLZglHcJzFuU09xGLgCnIV3P1QHaOzgMAUJe20fj7IZmtph75b4JE3kwmvF-M-Yo6QSEIIVd3-cj4QRAZnMJrBAIEAjFLSM5TVzZbAjU9rlUuV0CGsGriWZfhQHtk3Q1WhvfUmMH92Q437VlOB13-9hrpl8IPq7k5IbWgIx8E-5tFBC7T4PlJQg5xNkN4uDHCUbJF9HLzIVEyasQw6MOafyHVnhRo1L7fiCM'
  },
  {
    id: 'lead-generation',
    title: 'Lead Generation',
    description: 'Collect leads from people interested in your business.',
    image: 'https://lh3.googleusercontent.com/aida-public/AB6AXuB_G_Z1ZvNkelIFz_RmabJCaxVt98vEHR8zbEIbmsK-gVkN2peLYKiBkyrbyr9EltfMjKyuHgZusvHoHIon_xu0QWlm7hCoZPzoaq3KBpSCA-SYQ9yAjV4GgycruWi3tPpuCFmbMDa5ZzWPtg-RUH5fkgjSNegXamJnElbL0MGkWTJp7MTTvtKdK_G76W6zJuj-ZrJ-tUvO35ot8f2Q6dQQzqlF_vom9psJGOCTja7WffvUfb-uEuZi6LMd3ONzu02DFlkOxjgU-zM'
  },
  {
    id: 'sales',
    title: 'Sales',
    description: 'Find people likely to purchase your products or services.',
    image: 'https://lh3.googleusercontent.com/aida-public/AB6AXuB2DdYel9vZdKVLEpAyDHZ8aAatQmEvkyBdHoL7CB1ZE-vKo-Lb0Sh0mFJEmn6feiAebsXTMCxe-aUEttWbLhwA6jzKBA7hCFBusme9Pfm2HmwlwW7RdLT4Ha2PpYb8RJpKNnDcP3I3nTiqi6EPdGRqb_oJQX920Du9Uao9NIDVokrdD8jyALLQx2aFZWmJhoVbSgbPHSty-4ReoZx99j35AxXujhFgMn0xTo3Fg5h6-AOv37i7bL1tSVcy_e18MLHNfiOYxtSwfPc'
  },
  {
    id: 'store-traffic',
    title: 'Store Traffic',
    description: 'Drive foot traffic to your physical stores.',
    image: 'https://lh3.googleusercontent.com/aida-public/AB6AXuAzoHSPoSZ5RpUgCPE8COuIFfma9NKms76w8weaCAcPun3TD88Dme6Gov_DdteDN-cmMLUPEITPihi3_52Puqq14obuoTgYL-Voq_lyQ-tZaPu1yhRJFyFnHhNoFjdu0u-kXdu81cNdYhYUeOROJVY-VPm8GEpkCjCRZ2LzEUqQqCEAHvoenkwVW-sXTxv1YxUOCpkuCJfPdymJbDRK2veisLacA52Irbzc2I7HmQMJgLbnYOsqzLAFiFZNsYAMDnetBhI3SWi1nHo'
  }
]

export default function CampaignWizardPage() {
  const [selectedObjective, setSelectedObjective] = useState<string | null>(null)
  const router = useRouter()

  const steps = ['Objective', 'Audience', 'Creative', 'Budget', 'Review']
  const currentStep = 0

  const handleContinue = () => {
    if (selectedObjective) {
      // Navigate to next step or save progress
      console.log('Selected objective:', selectedObjective)
    }
  }

  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--background-dark)' }}>
      {/* Header */}
      <header className="flex items-center justify-between border-b px-10 py-4" style={{ borderColor: 'var(--border-color)' }}>
        <div className="flex items-center gap-4">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Create New Campaign
          </h2>
        </div>
        <div className="flex items-center gap-4">
          <label className="relative">
            <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-disabled)' }}>
              search
            </span>
            <input
              className="form-input w-64 rounded-lg border-none pl-10 pr-4 focus:outline-none focus:ring-2"
              style={{
                backgroundColor: 'var(--background-tertiary)',
                color: 'var(--text-primary)',
                focusRingColor: 'var(--primary-color)'
              }}
              placeholder="Search"
              type="text"
            />
          </label>
          <button
            className="flex items-center justify-center size-10 rounded-lg transition-colors"
            style={{ backgroundColor: 'var(--background-tertiary)' }}
          >
            <span className="material-symbols-outlined" style={{ color: 'var(--text-secondary)' }}>
              help
            </span>
          </button>
        </div>
      </header>

      {/* Main Content */}
      <div className="p-10">
        <div className="max-w-4xl mx-auto">
          {/* Progress Steps */}
          <div>
            <div className="flex justify-between mb-1 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
              {steps.map((step, index) => (
                <div
                  key={step}
                  className={index === currentStep ? 'font-bold' : ''}
                  style={{ color: index === currentStep ? 'var(--primary-color)' : 'var(--text-secondary)' }}
                >
                  <span>{step}</span>
                </div>
              ))}
            </div>
            <div className="relative h-1 w-full rounded-full" style={{ backgroundColor: 'var(--border-color)' }}>
              <div
                className="absolute h-1 rounded-full"
                style={{
                  backgroundColor: 'var(--primary-color)',
                  width: `${((currentStep + 1) / steps.length) * 100}%`
                }}
              />
            </div>
            <p className="text-sm font-normal leading-normal mt-2" style={{ color: 'var(--text-disabled)' }}>
              Step {currentStep + 1} of {steps.length}
            </p>
          </div>

          {/* Main Section */}
          <div className="mt-12">
            <h2 className="text-3xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
              Choose your objective
            </h2>
            <p className="mt-2" style={{ color: 'var(--text-muted)' }}>
              What's the main goal you want to achieve with this campaign?
            </p>

            {/* Objectives Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mt-8">
              {objectives.map((objective) => (
                <div
                  key={objective.id}
                  onClick={() => setSelectedObjective(objective.id)}
                  className={`rounded-lg overflow-hidden border transition-all cursor-pointer group ${
                    selectedObjective === objective.id
                      ? 'border-[var(--primary-color)]'
                      : 'border-transparent hover:border-[var(--primary-color)]'
                  }`}
                  style={{ backgroundColor: 'var(--background-secondary)' }}
                >
                  <div
                    className="h-40 bg-cover bg-center"
                    style={{ backgroundImage: `url("${objective.image}")` }}
                  />
                  <div className="p-5">
                    <h3 className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>
                      {objective.title}
                    </h3>
                    <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
                      {objective.description}
                    </p>
                  </div>
                </div>
              ))}
            </div>

            {/* Action Buttons */}
            <div className="mt-12 flex justify-end gap-4">
              <button
                className="px-6 py-2 rounded-md font-semibold transition-colors"
                style={{
                  color: 'var(--text-secondary)',
                  backgroundColor: 'var(--background-tertiary)'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = 'var(--border-color)'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'var(--background-tertiary)'
                }}
              >
                Save as Template
              </button>
              <button
                onClick={handleContinue}
                disabled={!selectedObjective}
                className="px-6 py-2 rounded-md font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                style={{
                  color: 'var(--text-primary)',
                  backgroundColor: 'var(--primary-color)'
                }}
                onMouseEnter={(e) => {
                  if (!e.currentTarget.disabled) {
                    e.currentTarget.style.backgroundColor = '#7c3aed'
                  }
                }}
                onMouseLeave={(e) => {
                  if (!e.currentTarget.disabled) {
                    e.currentTarget.style.backgroundColor = 'var(--primary-color)'
                  }
                }}
              >
                Continue
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}