import type { Metadata, Viewport } from 'next'
import { AuthProvider } from '@/lib/auth-context'
import './globals.css'
export const metadata: Metadata = { title: 'Knot — Talk freely', description: 'A thoughtful social space, protected by Aegis AI.', icons: { icon: '/icon.svg' } }
export const viewport: Viewport = { colorScheme: 'dark', themeColor: '#0B0F14', width: 'device-width', initialScale: 1, userScalable: true }
export default function RootLayout({children}:{children:React.ReactNode}){return <html lang="en" className="dark"><body className="antialiased"><AuthProvider>{children}</AuthProvider></body></html>}
