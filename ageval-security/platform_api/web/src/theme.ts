export type Theme = 'dark' | 'light'

export const THEME_STORAGE_KEY = 'sentinel-theme'

function apply(theme: Theme): void {
  document.documentElement.dataset.theme = theme
}

export function initTheme(): Theme {
  const theme: Theme = localStorage.getItem(THEME_STORAGE_KEY) === 'light' ? 'light' : 'dark'
  apply(theme)
  return theme
}

export function setTheme(theme: Theme): void {
  apply(theme)
  localStorage.setItem(THEME_STORAGE_KEY, theme)
}
